# REPORT.md

**Name:** Mayank Kumar  
**Roll No:** 114125062 

---

## A. Dangerous Patterns

I defined specific commands as dangerous because they can easily damage the system or allow unauthorized access. Here is the breakdown:

* **`rm -rf`**: This is very dangerous because it deletes files and whole directories completely without asking for any confirmation. 
* **`shutdown`**: I flagged this because a script shouldn't be able to just power off the server or system randomly.
* **`reboot`**: Similar to shutdown, this restarts the machine unexpectedly and can interrupt important running processes.
* **`mkfs`**: This command is used to format a filesystem. If a script runs this, it can wipe out an entire hard drive and destroy all data.
* **`curl | sh`**: This downloads a script from the internet and runs it directly in the shell. It's a huge security risk because you are running code without looking at it first.
* **`wget | bash`**: This is exactly like the curl command. It pulls code from a web server and immediately executes it.

---

## B. Why Env Lines Were Rejected

When cleaning the environment files, I made sure to reject lines that were unsafe or badly formatted. Here is why specific lines were blocked:

* **`PASSWORD=mysecret`**: Passwords should never be stored in plain text inside an environment file.
* **`TOKEN=abcd123`**: Tokens usually give access to APIs or databases, so they are sensitive secrets that shouldn't be here.
* **`JWT_SECRET=xyz123`**: The keyword "SECRET" means it holds highly sensitive data that could compromise the app.
* **`PATH=/tmp`**: I rejected this because scripts shouldn't be allowed to change system command paths. That can lead to running malicious software.
* **`KEY = value`**: This was rejected for bad formatting. Having spaces around the `=` sign breaks how variables are read in Linux.
* **`SERVER-NAME=prod`**: Variable names should only use letters, numbers, and underscores. Hyphens (`-`) are not allowed, so I rejected it.

---

## C. Technical Challenges

Building this script had a few tricky parts, especially when it came to checking files and handling edge cases. Here is how I solved them:

**1. Recursive file scanning**
It was a challenge to make sure the script checked every single file, even the ones hidden deep inside subfolders. Just writing a simple loop only checks the current folder. To solve this, I used the `find` command. It automatically digs through all the directories to grab every `.sh` and `.env` file so I didn't miss anything.

**2. Regex validation for variables**
Checking if a line in the `.env` file was written correctly was tough. I needed a way to check that the variable name only had uppercase letters, numbers, or underscores before the equals sign. I solved this by using Bash regular expressions (`^[A-Z0-9_]+=.*$`). This line of code acts like a strict filter that automatically drops anything with spaces or bad characters.

**3. Detecting sensitive keys easily**
I didn't want to write a messy, super-long `if` statement to check for every single bad word like `PASSWORD` or `TOKEN`. Instead, I created an array called `sensitive_keys` at the top of my script. For every line in the `.env` file, the script loops through that short array to see if there is a match. It made the code much cleaner and easier to read.

**4. Preventing the script from scanning its own output**
This was a really weird edge case! My script was reading `.env` files and creating new, safe versions called `.env.sanitized`. But the `find` command was picking up those newly created files and trying to scan them all over again, causing an endless loop. I fixed this by adding `! -name "*.sanitized"` to my `find` command, telling it to completely ignore those specific files.

**5. Permission handling**
Checking if a file was world-writable (meaning anyone on the computer could edit it) was confusing at first. I had to use the `stat` command to pull the exact permission string. Then, using `*w?`, I was able to match the string to see if the write permission was turned on for "others". Once I found those files, I used `chmod o-w` to safely lock them down.

---

## D. Final Repository Structure

Based on the project setup, here is how the final directory is organized:

```text
DEV_OPS/
│
|
├── vault_sweep.log
├── vault_sweep.sh
│
└── test_project/
    ├── a.sh
    ├── b.sh
    |──.env
    |──.env.sanitized
    ├── dangerous.sh
    ├── notes.txt
    └── scripts/
        └── c.sh
