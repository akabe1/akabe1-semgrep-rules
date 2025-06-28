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
       77 OS-COMMAND           PIC X(100).
       77 RETURN-CODE          PIC S9(4) COMP.

       PROCEDURE DIVISION USING USER-INPUT.

* --- OS Command Injection ---
       DISPLAY "Enter OS command to execute: ".
       * --- ruleid : vuln os-cmd-inj --- 
       ACCEPT OS-COMMAND.
       CALL 'SYSTEM' USING OS-COMMAND.
       
       
       * --- ruleid : vuln os-cmd-inj --- 
       ACCEPT USER-INPUT.
       STRING "ls /etc/hosts " DELIMITED BY SIZE
              USER-INPUT DELIMITED BY SIZE
              INTO OS-CMD
       CALL 'SYSTEM' USING OS-CMD.
       
       
       
       * --- ruleid : ok os-cmd-inj --- 
       ACCEPT OS-COMMAND.
       IF OS-COMMAND = "ls"
         CALL 'SYSTEM' USING OS-COMMAND
       ELSE
         DISPLAY "Command not allowed"
       END-IF.
       

       STOP RUN.
