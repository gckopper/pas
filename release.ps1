$env:GOARCH = "amd64"
$env:GOOS = "windows"
go build -o "PAS-64.exe" main.go
$env:GOARCH = "386"
go build -o "PAS-x86.exe" main.go
$env:GOARCH = "arm"
go build -o "PAS-ARM.exe" main.go
$env:GOARCH = "arm64"
go build -o "PAS-ARM64.exe" main.go
$env:GOOS = "android"
go build -o "PAS-ARM64android" main.go
$env:GOOS = "linux"
go build -o "PAS-ARM64" main.go
$env:GOARCH = "arm"
go build -o "PAS-ARM" main.go
$env:GOARCH = "386"
go build -o "PAS-x86" main.go
$env:GOARCH = "amd64"
go build -o "PAS-64" main.go
$env:GOOS = "windows"
