       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.

       DATA DIVISION.

       WORKING-STORAGE SECTION.
       77 INPUT-USER           PIC X(20).
       77 INPUT-TEST           PIC X(20).


       PROCEDURE DIVISION.                    
       
* --- Improper Error Handling ---
       EXEC SQL
       WHENEVER SQLERROR
       PERFORM HANDLE-ERR
       SQL-EXEC.

       HANDLE-ERR.
          * --- ruleid : vuln improper error handling ---
          STRING "Error status is: " DELIMITED BY SIZE
              SQLSTATE DELIMITED BY SIZE
              INTO ERR-STATUS
          OPEN ERR-FILE
          WRITE ERR-STATUS.
          END-WRITE
          CLOSE ERR-FILE
          
          
          
       * --- ruleid : vuln improper error handling ---
       DISPLAY "Error message is: " SQLERRMC.



       * --- ruleid : ok improper error handling ---
       DISPLAY "Error message is: " SQLERRD.


       STOP RUN.
