// Package entry. Declaring `import crypto from "../crypto";` loads this
// file and nothing else. Load a module with `import crypto.sha256;`.
// `goose tests/self_check.goose` runs every published vector.

fn ::main() {
    print("goose tests/self_check.goose");
}
