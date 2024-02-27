![](./.github/banner.png)

<p align="center">
  The ldapconsole script allows you to perform custom LDAP requests to a Windows domain.
  <br>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/ldapconsole">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
</p>

## Features

 - [x] Authentications:
   - [x] Authenticate with password
   - [x] Authenticate with LM:NT hashes (Pass the Hash)
   - [x] Authenticate with kerberos ticket (Pass the Ticket)
 - [x] Interactive mode
   - [x] Colored results
   - [x] Preset queries 
 - [x] Non-interactive mode
   - [x] Colored results
   - [x] Exportable to XLSX format with option `--xlsx`
  
## Requirements

For `python-ldap`:

```bash
sudo apt-get install libsasl2-dev python3-dev libldap2-dev libssl-dev
```

And then:

```bash
python3 -m pip install -r requirements.txt
```

## Examples

```bash
./ldapconsole.py -u 'user1' -p 'Admin123!' -d 'LAB.local' --dc-ip 192.168.2.1
```

![](./.github/example.png)

### Extract the list of the computers with an obsolete OS to an Excel file

```bash
./ldapconsole.py -d LAB.local -u Administrator -p 'Admin123!' --dc-ip 10.0.0.101 -q '(&(objectCategory=Computer)(|(operatingSystem=Windows 2000*)(operatingSystem=Windows Vista*)(operatingSystem=Windows XP*)(operatingSystem=Windows 7*)(operatingSystem=Windows 8*)(operatingSystem=Windows Server 200*)(operatingSystem=Windows Server 2012*)))' -a 'operatingSystem' -a 'operatingSystemVersion' -x ComputersWithObsoleteOSes.xlsx
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
