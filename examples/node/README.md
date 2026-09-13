# Node.js example

Install dependencies and calculate Streebog-256 or Streebog-512 for a file:

```sh
npm install
npm run hash -- path/to/document.pdf 256
npm run hash -- path/to/document.pdf 512
```

Create and immediately verify a detached CMS signature with the first private
key in a PFX container:

```sh
PFX_PASSWORD="your password" npm run sign:pfx -- key.pfx document.pdf document.pdf.p7s 256
```

In PowerShell, set the password only for the current process:

```powershell
$env:PFX_PASSWORD = Read-Host -MaskInput "PFX password"
npm run sign:pfx -- key.pfx document.pdf document.pdf.p7s 256
Remove-Item Env:PFX_PASSWORD
```

Use `512` as the final argument for a GOST R 34.10-2012 512-bit certificate.
The script rejects an incompatible choice. Do not put a real password in the
source code, command history, or a checked-in `.env` file.
