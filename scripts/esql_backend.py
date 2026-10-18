r"""ES|QL backend for dryfire: pySigma-backend-elasticsearch's ESQLBackend with two fixes.

The package's backend writes Sigma matches straight into ES|QL, but two things
behave differently on Elasticsearch (checked on 9.5.5, see CLAUDE.md, M5):

1. Case. Sigma string matches ignore case; ES|QL's `==`, `like`, `starts_with`,
   `ends_with` and `in` don't. This backend writes every string match as
   `to_lower(field)` against the lower-cased value. Matches marked `|cased`
   keep their case.

   Also for `like`: in a LIKE pattern a backslash escapes the next character,
   so a literal backslash (C:\Users\) must be doubled there. The package's
   backend doesn't, and Elasticsearch rejects `*\users\*`. This backend
   writes LIKE patterns itself, doubling literal backslashes and escaping
   literal * and ?.

2. Regex. Sigma regexes search anywhere in the value (like Python's
   re.search). ES|QL `rlike` uses Lucene regex, which must match the WHOLE
   value, has no `^`/`$` anchors and no case-insensitive flag. This backend
   rewrites a Sigma regex into a Lucene one:
     - wrap it as `.*(...).*` so it can match anywhere
     - a leading `^` drops the leading `.*`, a trailing `$` the trailing one
     - a first group starting with `^|` (e.g. `(^|:)x`, "start or after a
       colon") becomes `(.*(:))?x`; a last group ending with `|$` becomes
       `((...).*)?`
     - the `i` flag: `to_lower(field)` and the pattern's letters lower-cased
     - characters Lucene treats as operators (`"`, `#`, `@`, `&`, `<`, `>`,
       `~`) are escaped
   Anything else it can't translate exactly (anchors elsewhere, lookarounds,
   lazy quantifiers, back-references, `(?:`) raises an error, so the rule
   fails conversion instead of silently matching something different.
"""

from sigma.backends.elasticsearch import ESQLBackend
from sigma.conversion.state import ConversionState
from sigma.types import SigmaRegularExpression, SigmaRegularExpressionFlag, SigmaString, SpecialChars

# Characters that are operators in Lucene regex but plain characters in Sigma's.
LUCENE_ESCAPE = set('"#@&<>~')


class RegexNotTranslatable(NotImplementedError):
    pass


def lower_pattern(pattern):
    """Lower-case a regex's letters, but not the letter after a backslash (\\S stays \\S)."""
    out, i = [], 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2])
            i += 2
        else:
            out.append(pattern[i].lower())
            i += 1
    return "".join(out)


def matching_paren(pattern, start):
    """Index of the ')' that closes the '(' at `start` (escapes and [...] classes skipped)."""
    depth, i, in_class = 0, start, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise RegexNotTranslatable(f"unbalanced parentheses in regex: {pattern}")


def check_and_escape(pattern):
    """Refuse constructs Lucene can't do the same way; escape Lucene's extra operators."""
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            nxt = pattern[i + 1:i + 2]
            if nxt.isdigit() or nxt in ("b", "B", "A", "Z", "z"):
                raise RegexNotTranslatable(f"regex uses \\{nxt}, which Lucene doesn't support: {pattern}")
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c in "^$":
            raise RegexNotTranslatable(f"regex has a {c} anchor that can't be translated: {pattern}")
        elif c == "(" and pattern[i + 1:i + 2] == "?":
            raise RegexNotTranslatable(f"regex uses a (? group, which Lucene doesn't support: {pattern}")
        elif c in "*+?}" and pattern[i + 1:i + 2] == "?":
            raise RegexNotTranslatable(f"regex uses a lazy quantifier, which Lucene doesn't support: {pattern}")
        out.append("\\" + c if c in LUCENE_ESCAPE else c)
        i += 1
    return "".join(out)


def to_lucene(pattern):
    """Rewrite a Sigma (search-anywhere) regex as a Lucene (whole-value) regex. See the module docstring."""
    head, tail = ".*", ".*"
    if pattern.startswith("^"):
        pattern, head = pattern[1:], ""
    elif pattern.startswith("(^|"):
        end = matching_paren(pattern, 0)
        pattern = "(.*(" + pattern[3:end] + "))?" + pattern[end + 1:]
        head = ""
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern, tail = pattern[:-1], ""
    elif pattern.endswith("|$)"):
        # find the '(' that opens this last group
        start = next(i for i in range(len(pattern) - 1, -1, -1)
                     if pattern[i] == "(" and matching_paren(pattern, i) == len(pattern) - 1)
        pattern = pattern[:start] + "((" + pattern[start + 1:-3] + ").*)?"
        tail = ""
    # The rewrites above only add groups and `.*`, never anchors, so the check
    # below only sees what's left of the original pattern.
    return head + "(" + check_and_escape(pattern) + ")" + tail


def esql_string(text):
    """Quote text as an ES|QL string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def uses_like(value: SigmaString):
    """True when the package's backend would write this value as a `like` match:
    it has wildcards and isn't a plain starts-with or ends-with."""
    if not value.contains_special():
        return False
    if value.endswith(SpecialChars.WILDCARD_MULTI) and not value[:-1].contains_special():
        return False  # starts_with(...)
    if value.startswith(SpecialChars.WILDCARD_MULTI) and not value[1:].contains_special():
        return False  # ends_with(...)
    return True


def like_pattern(value: SigmaString):
    """The value as an ES|QL LIKE pattern: wildcards as * and ?, literal \\ * ? escaped."""
    out = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            out.append("*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append("?")
        elif isinstance(part, str):
            out.append(part.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?"))
        else:
            raise NotImplementedError(f"placeholder in value isn't supported: {value}")
    return "".join(out)


class DryfireESQLBackend(ESQLBackend):
    name = "dryfire ES|QL backend (case-insensitive strings, Lucene regex)"

    # While True, field names are written as to_lower(field) and string values lower-cased.
    _lowercase = False

    def escape_and_quote_field(self, field_name):
        field = super().escape_and_quote_field(field_name)
        return f"to_lower({field})" if self._lowercase else field

    def convert_value_str(self, s, state):
        value = super().convert_value_str(s, state)
        return value.lower() if self._lowercase else value

    def _lowercased(self, convert, *args):
        self._lowercase = True
        try:
            return convert(*args)
        finally:
            self._lowercase = False

    def convert_condition_field_eq_val_str(self, cond, state):
        if uses_like(cond.value):
            field = f"to_lower({super().escape_and_quote_field(cond.field)})"
            return f"{field} like {esql_string(like_pattern(cond.value).lower())}"
        return self._lowercased(super().convert_condition_field_eq_val_str, cond, state)

    def convert_condition_as_in_expression(self, cond, state):
        return self._lowercased(super().convert_condition_as_in_expression, cond, state)

    def convert_condition_field_eq_val_re(self, cond, state: ConversionState):
        regex: SigmaRegularExpression = cond.value
        pattern = str(regex.regexp)
        ignore_case = SigmaRegularExpressionFlag.IGNORECASE in regex.flags
        if regex.flags - {SigmaRegularExpressionFlag.IGNORECASE}:
            raise RegexNotTranslatable(f"regex flags other than i aren't supported: {pattern}")
        if ignore_case:
            pattern = lower_pattern(pattern)
        field = super().escape_and_quote_field(cond.field)
        if ignore_case:
            field = f"to_lower({field})"
        return f"{field} rlike {esql_string(to_lucene(pattern))}"
