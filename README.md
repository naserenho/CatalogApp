## Item Catalog project
This project is part of the series of the Full Stack NanoDegree program offered by Udacity.
In this project, the main task is to develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.
Language used is **Python v3**, and database module used is **sqlite** to connect to the database.

### Project files:

* application.py: Python code to send/receive requests (client and server) for the News page
* catalogdb.py: Database code for the Catalog DB
* client_secrets.json: File used for OAuth with Google+ used for signing-in users
* templates folder: contains all html files of the website
* static folder: contains css files and pictures used in the website
* README.md: Documentation of the project

### Requirements
* [VirtualBox](https://www.virtualbox.org/)
* [Vagrant](https://www.vagrantup.com/)
* [Python3](https://www.python.org/)
* For Windows: [Git Bash terminal](https://git-scm.com/downloads) (Mac users can use the default terminal)
* Flask library in Python: In Git Bash termnial `python3 -m pip install flask`

### Running the project
1. Open Git Bash terminal, and navigate to the vagrant folder inside the fullstack folder
2. Start the VirtualBox VM using the command `vagrant up`
3. Log into the VM using the command `vagrant ssh`
4. Go to the root folder, then navigate to vagrant using: `cd | cd /vagrant`
5. Navigate to the catalog folder using: `cd catalog`
6. In the terminal, run `python3 application.py`, then open your browser on localhost port 5000 [here](http://localhost:5000/)

### Expected output
##### Html Endpoint 
1. Main landing page displays all categories. Logged-in users can create categories.
2. Choosing a category will display the items inside the category with their details. Logged-in users can edit their own category or its items, add new items to their category, or delete the category or its items
3. Login button will take you to the login page to signup using Google+

##### JSON Endpoint
1. You can view the same content displayed in the html through the url:
    [http://localhost:5000/catalog/JSON](http://localhost:5000/catalog/JSON)
#### Author
Abdulrahim Naser Eddin, FullStack Nanodegree Cohort 4 of 1mac initiative