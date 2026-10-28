# Third-party events in the checked-in samples

Almost every event in this folder is synthetic (written for these tests; `"SampleSource": "synthetic"`,
AWS documentation account IDs such as `111122223333`, and documentation IP ranges).

A few benign samples also hold trimmed real events, so the negative tests include realistic activity.
Each of those events names its dataset, commit and file in its `SampleSource` field. They remain under
their dataset's licence, not this repo's MIT licence:

- **OTRF Security Datasets** (commit `d9d40ef`): MIT License, Copyright (c) 2021 Open Threat Research Forge.
  <https://github.com/OTRF/Security-Datasets>
- **EVTX-ATTACK-SAMPLES** (commit `4ceed2f`): GNU General Public License v3.0, by Samir Bousseaden.
  <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

| File | OTRF events | EVTX-ATTACK-SAMPLES events |
|---|---|---|
| `win_domain_admin_group_member_added_benign.json` | 1 |  |
| `win_lsass_access_from_user_path_benign.json` | 7 | 1 |
| `win_lsass_memory_access_benign.json` | 2 |  |
| `win_office_spawning_shell_or_script_host_benign.json` | 1 |  |
| `win_powershell_encoded_command_benign.json` | 1 | 2 |
| `win_privileged_builtin_group_member_added_benign.json` | 1 |  |
| `win_psexec_named_pipes_benign.json` |  | 6 |
| `win_renamed_shell_or_lolbin_benign.json` | 11 |  |
| `win_rundll32_suspicious_usage_benign.json` |  | 3 |
| `win_scheduled_task_suspicious_action_benign.json` | 2 |  |
| `win_service_install_suspicious_image_path_benign.json` | 1 |  |
