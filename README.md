![](./.github/banner.png)

<p align="center">
  The ldapconsole script allows you to perform custom LDAP requests to a Windows domain.
  <br>
  <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/ldapconsole">
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <br>
</p>

## Features

 - [x] Authenticate with password
 - [x] Authenticate with LM:NT hashes
 - [x] Authenticate with kerberos ticket

## Examples

```sh
./ldapconsole.py -u 'user1' -p 'Admin123!' -d 'LAB.local' --dc-ip 192.168.2.1
```

![](./.github/example.png)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
