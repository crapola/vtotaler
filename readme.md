## VTotaler

This Python script can be used to check local files against VirusTotal's database and output a summary to the console.
If a file hash is already known, it gives the last analysis result without uploading, otherwise the file is sent for analysis.

### Requirements

Python, the [official VirusTotal library](https://github.com/VirusTotal/vt-py), and a VirusTotal API key.

### Usage

Paste you API key in ```vtotaler/api_key.py```.

Navigate to the project root where the module folder is and run with:

	python vtotaler <path>

``` <path> ``` may point to a directory, a file or include a pattern.

On Windows, you can scan the Download folder using

	python vtotaler (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path