# Third-party events in the checked-in samples

Almost every event in this folder is synthetic (written for these tests; `"SampleSource": "synthetic"`,
AWS documentation account IDs such as `111122223333`, and documentation IP ranges).

A few benign samples also hold trimmed real events, so the negative tests include realistic activity.
Each of those events names its dataset, commit and file in its `SampleSource` field. They all come from
one dataset and remain under its licence:

- **OTRF Security Datasets** (commit `d9d40ef`): MIT License, Copyright (c) 2021 Open Threat Research Forge.
  <https://github.com/OTRF/Security-Datasets>

| File | OTRF events |
|---|---|
| `win_domain_admin_group_member_added_benign.json` | 1 |
| `win_lsass_access_from_user_path_benign.json` | 7 |
| `win_lsass_memory_access_benign.json` | 2 |
| `win_office_spawning_shell_or_script_host_benign.json` | 1 |
| `win_powershell_encoded_command_benign.json` | 1 |
| `win_privileged_builtin_group_member_added_benign.json` | 1 |
| `win_renamed_shell_or_lolbin_benign.json` | 11 |
| `win_scheduled_task_suspicious_action_benign.json` | 2 |
| `win_service_install_suspicious_image_path_benign.json` | 1 |

No EVTX-ATTACK-SAMPLES (GPL-3.0) events are checked in; that dataset is only downloaded at test time.

## OTRF Security Datasets licence

```
MIT License

Copyright (c) 2021 Open Threat Research Forge

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
