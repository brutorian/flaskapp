# Nevada Election Website
 
## Overview
 
### What is this website for?
This a website for an upcoming election for a new governor in the state of Nevada and what their policies are.
 
 
### What does it do?
The site informs the user of the Candidate who's running for the State of Nevada. It shows people what they intend to do such as what policies they intend to bring in and how they intend to get these polices to work.
The site also gives people the opportunity to make an account on the site to which they can log back into whenever they like.


### How does it work
 The site works by allowing the user to move around the site to view all of the policies and pages on the site. It has a responsive design which will appeal to users and keep them interested in looking further on in the site.
 This has:
• Login/Signup/Logout
• Account Page
• SQLALCHEMY/Postgres db
• Info pages


## Features
### Existing Features
• Navbar allowing user to navigate round the site
• CSS design 
### Features Left to Implement
- Show what user is currently logged in.
- Add flash text to the login to indicate user has logged in.


### Some the tech used includes:
This website uses:
• HTML (Hyper Text Markup Language)
• CSS (Cascading style sheets)
• Javascript (programming language)
• d3 (JavaScript library for interpreting data)
• Python (programming language)
• Sqlalchemy (ORM)
• Postgres (OMR)
• Flask (An open-source python web framework )
• Jinja (A template engine)
• Pycharm (A code editor recommended by the course)
• Sublime (A code editor recommended by the course)


## Testing
All components of the site were tested manually.
Navbar:
1.Click on the hamburger icon, this leads to nav bar sliding out to reveal the links to all the pages.
2.Once a link to a page is clicked it'll redirect to that page.
3.If it does'nt redirect then page has'nt been linked it correctly.

Login/Signup/Logout:
1.Tested to ensure the user can create an account allowing them to login and logout of the site.
2. Went to the signup page, if the account was successfully created then the user should be redirected to the login page, however if it did'nt the user would remain on the signup page.
3. If the user entered similar information in the signup such as email and username the page would remain on the signup page.
4. Once redirected to the login, user can login and if logged in successfully then I'd be redirected to the index page.
5. Once logged in the login and signup tabs in the navbar should be hidden and the logout tab should appear. When the logout tab was clicked, the account was logged out making the signup and login to appear.


## Contributing
 
 
### Getting the code up and running
Pycharm/Sublime:
1.Enter into the terminal and enter "python manage.py runserver",
2. Open the link in the terminal and you'll be directed to the page.

Github:
Follow the github deployment process also you can see it here().

Heroku:
Follow the heroku deployment process also you can see it here().


###Deployment
Github:
1. First, you will need to clone the repository by running the "git clone "" "command
2. Copy the files from the original folder into the new github one.
3. Once files added go to the terminal and run "git add ." .
4. As soon as it has finished compiling the files, then run in terminal "git commit -m "first push"".
5. Then Finally type in the terminal "git push origin master"
6. Go to your github repository and see it's all there.

Heroku:
1. Create a heroku account and log in, to log in you'll be required to type in "heroku login" in your terminal. Once the login has been verified you'll be logged in.
2. Go to the heroku dashboard, click on create new app, give it a name, select eu region then click create app.
3. Add postgresql to the add on link in the resources tab
4. Go to settings and comment out the sqlite database like so:
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' and change it to the postgres link provided by heroku add on.
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres.db'. This'll link your database up to the postgres one. 

5. Before deployment make sure you have placed SECRET_KEY into a config.py file and turned debugger to FALSE.
6. Click deploy and then the project should be up and running.


### Media
The photos used in this site were obtained from :
  • Google Images
  • Wikipedia 
  • State Seal (https://www.eventflags.com/nevada-state-seal-full-color-decal.html),
  • school (https://mapio.net/pic/p-58295000/),
  • nevada-home (https://www.google.co.uk/search?hl=en&biw=1536&bih=754&tbm=isch&sa=1&ei=ZtE7XKuYHZaO1fAP6YOz-AE&q=nevada+mountains&oq=nevada+mo&gs_l=img.3.0.0l10.51409.52159..53479...0.0..0.64.237.4......1....1..gws-wiz-img.......35i39j0i67.Dl-uzNQKZMU#imgrc=QFDLEjen_21CiM:),
  • 2(https://www.google.co.uk/search?hl=en&biw=1536&bih=754&tbm=isch&sa=1&ei=wNE7XKfEJPHCxgOF7JngCQ&q=nevada+state+capitol+building&oq=nevada+state+bui&gs_l=img.3.0.0i8i30l2j0i24l2j0i10i24.91483.95476..97007...0.0..0.68.527.9......1....1..gws-wiz-img.......35i39j0.msPAqFVrQbQ#imgdii=5vUA2p_lUDUo_M:&imgrc=-1SdXJH3Ya6XUM:),
  • 3 (https://www.pinterest.co.uk/pin/343821752788741865/),


### Content
The information I had used to create this site was from a number of sources:
    • Nevada Education Data Book (https://www.leg.state.nv.us/Division/Research/Publications/EdDataBook/2017/2017EDB.pdf),
    • Biggest Issues Facing Nevada (http://www.sossnv.org/archived-results/results/nevada-as-a-place-to-live/biggest-issues-facing-nevada/),
    • Nevada (https://en.wikipedia.org/wiki/Nevada),
    • Nevada Government Website (http://rccd.nv.gov/),
    • D3 Piechart (http://bl.ocks.org/enjalot/1203641),
    • D3 Piechart (http://bl.ocks.org/clayzermk1/4290070),
    • D3 Piechart (http://www.cagrimmett.com/til/2016/08/19/d3-pie-chart.html),
    • D3 Barchart (https://medium.freecodecamp.org/how-to-create-your-first-bar-chart-with-d3-js-a0e8ea2df386),
    • D3 Barchart (https://blog.risingstack.com/d3-js-tutorial-bar-charts-with-javascript/),
    • Jinja Templates (http://jinja.pocoo.org/),
    • MYSQL Signup (https://code.tutsplus.com/tutorials/creating-a-web-app-from-scratch-using-python-flask-and-mysql--cms-22972),
    • MYSQL Signup (https://www.bogotobogo.com/python/Flask/Python_Flask_Blog_App_Tutorial_1.php),
    • MYSQL Login(https://www.youtube.com/watch?v=e360Gm07oRw),
    • MYSQL Login (https://realpython.com/introduction-to-flask-part-2-creating-a-login-page/),
    • MYSQL Login (https://gist.github.com/alvesjnr/1005481),
    • MYSQL Hash (https://dev.to/kaelscion/authentication-hashing-in-sqlalchemy-1bem),
    • MYSQL Hash (https://stackoverflow.com/questions/50121432/flask-authenticate-hashed-password-from-sqlalchemy),
    • MYSQL Hash (https://pythonprogramming.net/password-hashing-flask-tutorial/),
    • Authentication (https://scotch.io/tutorials/authentication-and-authorization-with-flask-login),
    • Authentication (https://blog.openshift.com/use-flask-login-to-add-user-authentication-to-your-python-application/),
    • sha256_crypt (https://passlib.readthedocs.io/en/stable/lib/passlib.hash.sha256_crypt.html),
    • sha256_crypt (https://www.youtube.com/watch?v=UtF58KqcHWU&t=15s),
    • Engine (https://docs.sqlalchemy.org/en/13/dialects/mysql.html),
    • Engine (odingforentrepreneurs.com/courses/ecommerce/products-component/),
    • Engine (https://stackoverflow.com/questions/29355674/how-to-connect-mysql-database-using-pythonsqlalchemy-remotely),
    • Engine (https://www.youtube.com/watch?v=8aTnmsDMldY),
    • Sessions maker(https://docs.sqlalchemy.org/en/latest/orm/session_api.html),
    • JS Slideshow (https://www.w3schools.com/howto/howto_js_slideshow.asp),
    • Flask Flash (http://flask.pocoo.org/docs/1.0/patterns/flashing/),
    • SQLALCHEMY (https://www.youtube.com/watch?v=rJGMOOSnHL0),
    • SQLALCHEMY (https://www.youtube.com/watch?v=CSHx6eCkmv0&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH&index=6),
    • SQLALCHEMY (https://www.youtube.com/watch?v=d04xxdrc7Yw&t=1406s),
    • Colours (https://htmlcolorcodes.com/),
    • Facebook (https://www.facebook.com/NVSOS/),
    • Twitter (https://twitter.com/nvgovernment?lang=en),
    • login (https://stackoverflow.com/questions/12075535/flask-login-cant-understand-how-it-works),
    • login (https://flask-login.readthedocs.io/en/latest/),
    • login (http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/),
    • login (https://stackoverflow.com/questions/28575234/login-required-trouble-in-flask-app),
    • login (https://www.reddit.com/r/flask/comments/6n8udc/flasklogin_vs_flasksecurity_in_2017/),
    • bcrypt (https://flask-bcrypt.readthedocs.io/en/latest/)
    • Code Institute Course
    

