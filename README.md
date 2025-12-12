# NileDefender

## Descripton 
NileDefender is a self-hosted security tool engineered for penetration testers and development teams. It provides a flexible framework for conducting comprehensive web application security tests through a unified web interface.



# Pages Design 
https://excalidraw.com/#json=oSrZnZ1vgoIohU6cgz77o,zaioTUhpKSf5YYQ9UVrsIA

# System Arch
https://excalidraw.com/#json=opjfKkRATAPZveyIDOy9I,2x7sTI-w_oYqYZ4ZfMcQCg



# Set up 

## Install all dependencies
* pip3 install -r requirements.txt
* pip3 install -r req.txt


## install python Libraries manually

### install manually:
 - pip3 install requests dnspython beautifulsoup4 sqlalchemy lxml urllib3


### install external tools
- go is required

- httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

### python version that's used => 3.13
## For testing script of recon 

- python recon_workflow.py -d http://testphp.vulnweb.com/ --passive
