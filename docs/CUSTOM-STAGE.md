# Custom Stage Escape Hatch

Dokumen ini menjelaskan spesifikasi dan kontrak integrasi untuk memperluas Cerberus dengan stage custom (`stage: "custom:<x>"`). Sesuai [ADR-0002](file:///Users/nicholasandriansurjadi/Documents/cerberus/docs/adr/ADR-0002-universal-gateway.md), Cerberus didesain sebagai Universal Policy Gateway: penambahan domain baru tidak memerlukan kompilasi ulang kode Go inti engine.

---

## 1. Kontrak Input (`stage: custom:<x>`)

Setiap evaluasi stage custom dikirim melalui endpoint seragam `POST /v1/decide` dengan format JSON:

```json
{
  "stage": "custom:<name>",
  "key_id": "<agent_or_caller_key>",
  "action": "<action>",
  "resource": "<target_resource>",
  "args": {
    "approved": false,
    "approval_id": "appr-12345",
    "...": "bebas"
  },
  "context": {
    "source_ip": "10.0.1.5",
    "timestamp": 1700000000
  }
}
```

### Penjelasan Field
- **`stage`**: String dengan format `custom:<name>` (misal `custom:terraform`, `custom:ci`, `custom:approval`) atau `custom_<name>`.
- **`key_id`**: Kredensial identitas agen atau pemanggil yang terdaftar pada `data.agents`.
- **`action`**: Operasi yang hendak dieksekusi (contoh: `plan`, `apply`, `deploy`, `promote`).
- **`resource`**: Target sumber daya (contoh: `workspace:production`, `repo:backend`).
- **`args`**: Parameter payload bebas (JSON object) yang dievaluasi oleh aturan Rego.
- **`context`**: Metadata kontekstual tambahan (IP sumber, waktu, dll).

---

## 2. Mekanisme Dispatch dan Package Naming

Dalam Rego, nama package tidak dapat mengandung karakter titik dua (`:`). Cerberus menggunakan konvensi penamaan:
- Nama file: `policies/stages/custom_<name>.rego`
- Deklarasi package: `package stages.custom_<name>`
- Output verdict: Rule `decision` (berupa object `{"decision": "allow"|"deny", "rule_id": "<id>", "reason": "<string>"}`).

Engine Cerberus (`policies/gateway/authz.rego` dan `internal/policy/loader.go`) secara dinamis memetakan:
1. Paket `stages.custom_<name>` diekstrak dan didaftarkan sebagai known stages baik sebagai `custom_<name>` maupun `custom:<name>`.
2. Saat request dengan `stage: "custom:<name>"` masuk ke `gateway.authz.decision`, stage di-resolve ke `data.stages.custom_<name>.decision`.
3. Pemeriksaan key gate (kill switch, bypass unknown keys, API key sha256) tetap berjalan sebelum verdict custom dieksekusi.

---

## 3. Contoh Lengkap: Stage `custom:terraform`

Berikut adalah contoh lengkap pembuatan stage `custom:terraform` untuk mengamankan eksekusi Terraform:
- **`plan`**: Selalu diizinkan (read-only).
- **`apply`**: Wajib memiliki approval eksplisit (`args.approved == true`, `args.approval_id != ""`, atau agen memiliki hak istimewa).
- **Aksi tidak dikenal**: Ditolak fail-closed (`custom.terraform.action_invalid`).

### 3.1 Aturan Rego (`policies/stages/custom_terraform.rego`)

```rego
package stages.custom_terraform

import rego.v1

decision := tf_decision

args := object.get(input, "args", {})
action := lower(object.get(args, "action", object.get(input, "action", "")))
resource := object.get(args, "resource", object.get(input, "resource", ""))
agent := object.get(data.agents, input.key_id, {})

valid_actions := ["plan", "apply", "refresh", "show", "output"]

is_approved if object.get(args, "approved", false) == true
is_approved if {
    appr := object.get(args, "approval_id", "")
    is_string(appr)
    appr != ""
}
is_approved if agent.allow_terraform_apply == true
is_approved if agent.prod_access == true

tf_decision := {
    "decision": "deny",
    "rule_id": "custom.terraform.action_invalid",
    "reason": sprintf("action %q is invalid for terraform (allowed: %v)", [action, valid_actions]),
} if {
    not action in valid_actions
} else := {
    "decision": "deny",
    "rule_id": "custom.terraform.apply_without_approval",
    "reason": sprintf("terraform apply on %q requires prior approval or elevated privilege", [resource]),
} if {
    action == "apply"
    not is_approved
} else := {
    "decision": "allow",
    "rule_id": "custom.terraform.allow_apply",
    "reason": sprintf("terraform apply on %q approved", [resource]),
} if {
    action == "apply"
    is_approved
} else := {
    "decision": "allow",
    "rule_id": "custom.terraform.allow_plan",
    "reason": sprintf("terraform plan on %q permitted", [resource]),
} if {
    action == "plan"
} else := {
    "decision": "allow",
    "rule_id": "custom.terraform.allow_read",
    "reason": sprintf("terraform read action %q permitted", [action]),
}
```

### 3.2 Contoh Uji Rego (`policies/stages/custom_terraform_test.rego`)

```rego
package gateway.custom_terraform_test

import rego.v1
import data.gateway.authz.decision

fixture_agents := {
    "k-dev": {"allow_terraform_apply": false, "prod_access": false},
    "k-sre": {"allow_terraform_apply": true, "prod_access": true},
}

decide(inp) := out if {
    out := decision with input as inp
        with data.config as data.testdata.config
        with data.teams as data.testdata.teams
        with data.agents as fixture_agents
        with data.blocked_patterns as data.testdata.blocked_patterns
        with data.domains as data.testdata.domains
        with data.prod_shield as data.testdata.prod_shield
}

test_terraform_plan_allowed if {
    out := decide({
        "stage": "custom:terraform",
        "key_id": "k-dev",
        "action": "plan",
        "resource": "env/staging",
    })
    out.decision == "allow"
    out.rule_id == "custom.terraform.allow_plan"
}

test_terraform_apply_unapproved_denied if {
    out := decide({
        "stage": "custom:terraform",
        "key_id": "k-dev",
        "action": "apply",
        "resource": "env/prod",
    })
    out.decision == "deny"
    out.rule_id == "custom.terraform.apply_without_approval"
}

test_terraform_apply_approved_allowed if {
    out := decide({
        "stage": "custom:terraform",
        "key_id": "k-dev",
        "action": "apply",
        "resource": "env/prod",
        "args": {"approval_id": "ticket-789"},
    })
    out.decision == "allow"
    out.rule_id == "custom.terraform.allow_apply"
}
```

---

## 4. Konfigurasi Data JSON (`data.stages`)

Jika aturan custom memerlukan konfigurasi eksternal atau allowlist yang dapat di-update tanpa mengubah file Rego, masukkan konfigurasi ke dalam seksi `"stages"` pada `data/prod.json`:

```json
{
  "stages": {
    "custom_terraform": {
      "protected_workspaces": ["prod", "payments-infra"],
      "allowed_actions": ["plan", "apply", "output"]
    }
  }
}
```

Aturan Rego dapat langsung merujuk ke data tersebut melalui `data.stages.custom_terraform.protected_workspaces`.

---

## 5. Deployment dan Hot Reload

Penambahan file custom stage baru ke `policies/stages/` dapat langsung diaktifkan dengan:
1. **Reload Lokal / Dev**:
   ```bash
   kill -HUP $(pgrep cerberus)
   # atau kirim POST /v1/admin/reload
   curl -X POST http://127.0.0.1:8089/v1/admin/reload \
        -H "Authorization: Bearer $CERBERUS_ADMIN_TOKEN"
   ```
2. **Bundle Update (Produksi / Cluster)**:
   ```bash
   bin/cerberus-bundle build -signing-key keys/bundle.ed25519 -policies policies/ -data data/prod.json -out bundle.tar.gz
   curl -X POST http://127.0.0.1:8089/v1/admin/bundle \
        -H "Authorization: Bearer $CERBERUS_ADMIN_TOKEN" \
        --data-binary @bundle.tar.gz
   ```
Engine akan melakukan swap atomik tanpa zero-downtime, dan seluruh node di dalam cluster otomatis melakukan gossip sync.
