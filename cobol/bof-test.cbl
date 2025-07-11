       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.

       DATA DIVISION.

       WORKING-STORAGE SECTION.
       77 LONG-INPUT           PIC X(20).
       77 SHORT-FIELD          PIC X(05).
       77 TINY                 PIC X(20).
       77 BIG                  PIC X(50).
       77 SOURCE-FIELD         PIC X(20).
       77 DEST-FIELD           PIC X(10).
       77 MAX-LEN              PIC 9 VALUE 10.
       77 RETURN-CODE          PIC S9(4) COMP.

       PROCEDURE DIVISION.
       

      * --- Buffer Overflow ---
       DISPLAY "Enter a long string (max 20 chars): ".
       * --- ruleid : vuln bof ---
       ACCEPT LONG-INPUT.                              
       MOVE LONG-INPUT TO SHORT-FIELD.                   

       
       DISPLAY "Enter a long string (max 50 chars): ".
       * --- ruleid : vuln bof ---
       ACCEPT BIG.                              
       MOVE BIG TO TINY.   
       
       
       * --- ruleid : ok bof ---
       ACCEPT SOURCE-FIELD
       IF FUNCTION LENGTH(SOURCE-FIELD) <= MAX-LEN
           MOVE SOURCE-FIELD(1:MAX-LEN) TO DEST-FIELD
       ELSE
           DISPLAY "Error: input too big"
       END-IF


       STOP RUN.
