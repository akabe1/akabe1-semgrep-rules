       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.

       DATA DIVISION.
       LINKAGE SECTION.
       01 USER-INPUT.
          05 USERNAME  PIC X(10).
          05 PIN       PIC X(08).
          05 FILEPATH  PIC X(20).
       01  test-var    pic x(10).
       
       
       FILE SECTION.

       WORKING-STORAGE SECTION.
       77 MQ-COMMAND           PIC X(100).
       77 RETURN-CODE          PIC S9(4) COMP.

       PROCEDURE DIVISION USING USER-INPUT.
       
       
* --- MQ Command Injection ---
       DISPLAY "Enter MQ command to execute: ".
       * --- ruleid : vuln mq-cmd-inj --- 
       ACCEPT MQ-COMMAND.
       CALL 'MQCONN' USING MQ-COMMAND.                     


       * --- ruleid : vuln mq-cmd-inj --- 
       ACCEPT USER-INPUT.
       STRING USER-INPUT DELIMITED BY SIZE
              " MQ" DELIMITED BY SIZE
              INTO MQ-CMD
       CALL 'MQSET' USING MQ-CMD.
       
 

       STOP RUN.
