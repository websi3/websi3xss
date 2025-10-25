
   
|Xss|Xss Vulnerability Scanner|for web application|
|----------------|--------------|-------------|
|`Cross Site Scripting (XSS)`|

</div>

<hr>

<br>
<br>
<br>


| Features                          | About                                                                       |
|-----------------------------------|-----------------------------------------------------------------------------|
| `XSS Scanner`                     | Identify Cross-Site Scripting vulnerabilities.                              |
| `Customizable Payloads`           | Adjust payloads to suit specific targets.                                   |
| `Success Criteria`                | Modify success detection criteria for specific use cases.                   |
| `User-friendly CLI`               | Simple and intuitive command-line interface.                                |
| `Save Vulnerable URLs`            | Option to save vulnerable URLs to a file for future reference.              |
| `HTML Report Generation`          | Generates a detailed HTML report of found vulnerabilities.                  |
<!-- | `Share HTML Report `  | Share HTML vulnerability reports directly                | -->

<br>
<hr>
<br>
<br>



<br>
<hr>
<br>

## Installation

### Clone the repository

```bash
https://github.com/websi3/websi3xss.git
```
```bash
cd websi3xss
```

### Install the requirements
```bash
python3 -m venv venv                                                                                                                                              
source venv/bin/activate
```
```bash
pip3 install -r requirements.txt
```

### Run 

python3 websi3xss.py --url "http://target.example.com/?next=" --payloads xss.txt --report "/home/kali/automation/my custom xss/myxss/results.html" --always-report
                                                                      |




