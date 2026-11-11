# Example logs

All of these are real race detector output, except where a file says otherwise.

| File | How it was made |
|---|---|
| `shop-v1.log` | `go test -race ./inventory/ ./healthy/ ./cmd/...` in `../programs`, Go 1.27.3, linux/arm64 |
| `shop-v1-verbose.log` | The same with `-v` |
| `shop-v1.json` | The same with `-json` |
| `shop-v2.log` | The same with `-tags v2`: the cache race is fixed and a new counter race is added |
| `healthy.log` | `go test -race ./healthy/`: no races |
| `warm.log` | `go run -race ./cmd/warm`: output from a program, not a test |
| `testonly.log` | `go test -race ./testonly/`: races only in test code |
| `go1.22/shop-v1.log` | `go test -race ./...` with Go 1.22.12 |
| `written/github-actions.log` | Not real CI output: `shop-v1.log` with GitHub Actions style timestamps added to each line |
| `real/logrus-fbf9913-before.log` | [logrus](https://github.com/sirupsen/logrus) (MIT) at the parent of commit `fbf9913`, with that commit's `entry_test.go`, `go test -race .` |
| `real/logrus-fbf9913-after.log` | logrus at `fbf9913`, `go test -race ./...`: no races |
| `real/logrus-6ef0748.log` | logrus at `6ef0748`, its latest commit on 2026-11-01, `go test -race ./...`: no races |
| `windows-paths.log` | Synthetic Windows-style race report used by the parser unit test; not captured from a real Windows run |
| `real/zap-7c80d7b-before.log` | [zap](https://github.com/uber-go/zap) (MIT) at the parent of commit `7c80d7b`, with that commit's `lazy_with_test.go`, `go test -race ./zapcore/` |

Races depend on timing, so `make logs` can produce different counts. The tests expect the files as committed.
