       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.

       DATA DIVISION.

       FILE SECTION.
       FD DEBUG-FILE.
       01 DEBUG-RECORD.
          05 DEBUG-STR1     PIC X(20).
          01 DEBUG-STR2     PIC X(80).

       WORKING-STORAGE SECTION.


       PROCEDURE DIVISION.
       
* --- Debug ---      
      * --- ruleid : vuln debug display write ---
      D  DISPLAY "This is a debugging line".

      
         ACCEPT INPUT-USER
      D  OPEN INPUT DEBUG-FILE
      D  MOVE 'Debug row' TO DEBUG-STR1
      * --- ruleid : vuln debug display write ---
      D  WRITE DEBUG-RECORD
         END-WRITE
      * --- ruleid : vuln debug display write ---
      D  DISPLAY 'Closing file'.
      D  CLOSE DEBUG-FILE
      
      
      * --- ruleid : ok debug display write ---
      * D  DISPLAY 'Disabled debug line'.
      
      
      * --- ruleid : ok debug display write ---
         DISPLAY "Not a debugging line".
         
      
         MOVE "Not a debugging line" A-VAR
         OPEN INPUT A-FILE
      * --- ruleid : ok debug display write ---
         WRITE A-VAR
         CLOSE A-FILE

       STOP RUN.
