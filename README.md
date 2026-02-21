# ResultVista

## Overview
ResultVista is a comprehensive solution designed to streamline the process of result for educational institutions. This project focuses on providing users with easy access to results, analytics functionalities.

## Features
- **User-Friendly Interface:** An intuitive interface for easy navigation.
- **Calculate Result:** User upload the excel file with our requirement than user get a result table which have **total, percentage, grade, status**
- **Analytics Dashboard:** Visual representation of data to help analyze performance trends.
- **Download file:** User can download the result table in form of **excel file**, and also user can download the **chart PDF**.
- **Mail Integration:** When user create new account or delete account, user will get a confirmatioin mail.
- **Individual Student:** User can see any student result individually by clicking on row and if user want to share result to that student than enter email id of that student and the result PDF will be sent.

## Setup Instructions
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Gajera-Ansh/ResultVista.git
   cd ResultVista
   ```

2. **Install Libraries:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configuration:**
   Create a `.env` file in the root directory and add the necessary configuration variables as per the `.env.example` file.

4. **Database setup:**
   ## In app.py
   1. uncomment line no. 39
   2. comment line no. 40
   open XAMPP and create a database **user**.

6. **Run the project:**
   run app.py file and click on the first link

## Usage Guidelines
- **Logging In:** Use your credentials to log into the application. 
- **Upload excel file:** Upload excel file which in **example/Student_Marksheet_50_Students.xlsx** than click on **upload and validate** button
- **Generating Result:** after clicking on **upload and validate** button scroll down and click on **Process Results**

