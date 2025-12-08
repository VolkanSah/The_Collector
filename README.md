# The Collector.py (lite)
###### EDU Version to learn
**Warning: This tool is only for educational and ethical hacking purposes. Do not use it for any malicious activities. Use at your own risk.**

The Collector.py (lite) is a RedTeam Black-Python Script designed to help in finding BAD sites. This script is part of a larger collection and was created to be used with caution. Some functions have been removed to prevent any malicious attacks, but it remains a simple yet powerful script that can be used to scan for bad sites.

## Installation
To use The Collector.py (lite), you need to have Python 3 installed on your machine, as well as the following Python packages: requests, progress, and BeautifulSoup.

You can install the required packages by running the following command:

```shell
pip install requests progress BeautifulSoup4
```
## How it works
The Collector.py (lite) works by scraping a given URL and all its links, then searching for a specified keyword within the HTML content. If the keyword is found, the URL is added to a list of bad sites.

The script uses the requests package to make HTTP requests, BeautifulSoup to parse the HTML content, and progress to display a progress bar during the scanning process.

## Usage
To use The Collector.py (lite), simply run the script and provide the starting URL and the keyword you want to search for as command-line arguments:

```shell
python3 collector.py <starting_url> <keyword>
```
For example, to search for the keyword "child abuse" on the website "https://example.com", you would run:
```shell
python3 collector.py https://example.com "child abuse"
```
For better work! Setup collector.py to your needs and use

```shell
python3 collector.py
```

The script will then start scanning the website and all its links for the specified keyword. Any URLs that contain the keyword will be added to the list of bad sites.

The results are saved to a text file called collector_domainlist.txt in the same directory as the script. The file contains a list of all the visited URLs, along with a label indicating whether the site is a bad site or not.

## Disclaimer
The Collector.py (lite) is only intended for ethical hacking and educational purposes. Do not use this tool for any illegal activities. The author of this tool is not responsible for any damages caused by the misuse of this tool.

### Use at your own risk! Better with Tor rooted traffic to scan target onion sites!

### Thank you for your support!
- If you appreciate my work, please consider [becoming a 'Sponsor'](https://github.com/sponsors/volkansah), giving a :star: to my projects, or following me. 
### Copyright
- [VolkanSah on Github](https://github.com/volkansah)
- [Developer Site](https://volkansah.github.io)

### License
This project is licensed under the MIT - see the [LICENSE](LICENSE) file for details.
