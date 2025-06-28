       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370 WITH DEBUGGING MODE.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.

       DATA DIVISION.

       WORKING-STORAGE SECTION.
       77 SQL-QUERY            PIC X(200).
       77 SQL-QUERY-PERP       PIC X(200)
            VALUE "SELECT * FROM USERS WHERE NAME = :USER-NAME".
       77 USER-NAME            PIC X(50).
       77 CLIENT-ID            PIC X(50).
       

       PROCEDURE DIVISION.

* --- SQL Injection ---
       DISPLAY "Enter customer name for SQL query: ".
       * --- ruleid : vuln sqli ---
       ACCEPT INPUT-USER.                               
       STRING "SELECT * FROM CUSTOMERS WHERE NAME = '" DELIMITED BY SIZE
              INPUT-USER DELIMITED BY SIZE
              "'" INTO SQL-QUERY
       END-STRING.
       EXEC SQL
           EXECUTE IMMEDIATE :SQL-QUERY                    
       END-EXEC.
       
       
       * --- ruleid : vuln sqli ---
       ACCEPT USER-NAME
       MOVE "SELECT * FROM USERS WHERE NAME = '" TO SQL-QUERY
       STRING SQL-QUERY DELIMITED BY SIZE
              USER-NAME DELIMITED BY SPACE
              "'"
              INTO SQL-QUERY
       EXEC SQL
            EXECUTE IMMEDIATE :SQL-QUERY
       END-EXEC.
       
             
       
       * --- ruleid : ok sqli (host-var with prepare and execute)  ---
       DISPLAY "Enter the employee username:"
       ACCEPT WS-USERNAME
       MOVE WS-USERNAME TO HV-USERNAME
       MOVE "SELECT EMPNAME FROM EMPLOYEES WHERE USERNAME = ?" TO SQL-STMT
       EXEC SQL
           PREPARE STMT1 FROM :SQL-STMT
       END-EXEC
       EXEC SQL
           EXECUTE STMT1 INTO :HV-EMPNAME USING :HV-USERNAME
       END-EXEC
       
       
       
       * --- ruleid : ok sqli ---
       ACCEPT USER-NAME
       EXEC SQL
           PREPARE STMT FROM :SQL-QUERY-PREP
       END-EXEC
       EXEC SQL
           DECLARE CURSOR1 CURSOR FOR STMT
       END-EXEC
       EXEC SQL
           OPEN CURSOR1 USING :USER-NAME
       END-EXEC
       EXEC SQL
           CLOSE CURSOR1
       END-EXEC
       
       

       * --- ruleid : ok sqli (host-var) ---
       ACCEPT CLIENT-ID          
       EXEC SQL
          SELECT * FROM CLIENTS WHERE ID = :CLIENT-ID
       END-EXEC
        
        
       
       * --- ruleid : vuln sqli ---
       ACCEPT Y
       STRING "INSERT INTO TBL (a,b,c) VALUES (" X "," Y "," Z ")" INTO Q-SQL
       EXEC SQL PREPARE STMT FROM :Q-SQL END-EXEC.
       EXEC SQL EXECUTE STMT END-EXEC.
       

       
       * --- ruleid : ok sqli (host-var with cursor) ---
       ACCEPT HV-DEPT
       EXEC SQL
           DECLARE C1 CURSOR FOR
           SELECT EMPNAME FROM EMPLOYEES WHERE DEPT = :HV-DEPT
       END-EXEC
       EXEC SQL OPEN C1 END-EXEC
       EXEC SQL FETCH C1 INTO :HV-EMPNAME END-EXEC
       IF SQLCODE = 0
           DISPLAY "Employee: " HV-EMPNAME
       EXEC SQL FETCH C1 INTO :HV-EMPNAME END-EXEC
       IF SQLCODE = 0
           DISPLAY "Employee: " HV-EMPNAME
       EXEC SQL FETCH C1 INTO :HV-EMPNAME END-EXEC
       IF SQLCODE = 0
           DISPLAY "Employee: " HV-EMPNAME
       EXEC SQL CLOSE C1 END-EXEC
       
       

       STOP RUN.
