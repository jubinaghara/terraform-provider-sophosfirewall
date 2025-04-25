Create new release tag: git tag v1.0.2
Push to git: git push origin v1.0.2 

Create binaries
GOOS=linux GOARCH=amd64 go build -o terraform-provider-sophosfirewall_1.0.3_linux_amd64
GOOS=windows GOARCH=amd64 go build -o terraform-provider-sophosfirewall_1.0.3_windows_amd64.exe
GOOS=darwin GOARCH=amd64 go build -o terraform-provider-sophosfirewall_1.0.3_darwin_amd64

Zip the binaries
zip terraform-provider-sophosfirewall_1.0.3_linux_amd64.zip terraform-provider-sophosfirewall_1.0.3_linux_amd64
zip terraform-provider-sophosfirewall_1.0.3_windows_amd64.zip terraform-provider-sophosfirewall_1.0.3_windows_amd64.exe
zip terraform-provider-sophosfirewall_1.0.3_darwin_amd64.zip terraform-provider-sophosfirewall_1.0.3_darwin_amd64


sha256sum terraform-provider-sophosfirewall_1.0.3_*.zip terraform-provider-sophosfirewall_1.0.3_manifest.json > terraform-provider-sophosfirewall_1.0.3_SHA256SUMS


gpg --output terraform-provider-sophosfirewall_1.0.3_SHA256SUMS.sig --detach-sign terraform-provider-sophosfirewall_1.0.3_SHA256SUMS
