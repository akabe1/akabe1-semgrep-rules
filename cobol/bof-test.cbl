       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEMGREP-TEST-COBOL.
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION
       SOURCE-COMPUTER. IBM-370
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT CUSTOMER-FILE ASSIGN TO CUSTOMER-FILE-NAME
               ORGANIZATION IS LINE SEQUENTIAL
               FILE STATUS IS FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD CUSTOMER-FILE.
       01 CUSTOMER-RECORD PIC X(80).


       WORKING-STORAGE SECTION.
       77 DATA-PTR             USAGE POINTER.
       77 LONG-INPUT           PIC X(20).
       77 SHORT-FIELD          PIC X(05).
       77 INPUT-USER           PIC X(20).
       77 INPUT-PASS           PIC X(20).
       77 TINY                 PIC X(20) BASED.
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
       ALLOCATE 10 CHARACTERS INITIALIZED RETURNING DATA-PTR
       SET ADDRESS OF SHORT-FIELD TO DATA-PTR                           
       MOVE LONG-INPUT TO SHORT-FIELD. 
       

       DISPLAY "Enter a long string (max 20 chars): ".
       * --- ruleid : ok bof ---
       ACCEPT LONG-INPUT.                              
       MOVE LONG-INPUT TO SHORT-FIELD.                   


       DISPLAY "Enter a long string (max 50 chars): ".
       * --- ruleid : ok bof ---
       ACCEPT BIG.                              
       MOVE BIG TO TINY. 
       
       
       DISPLAY "Enter a long string (max 50 chars): ".
       * --- ruleid : vuln bof ---
       ACCEPT BIG.
       ALLOCATE TINY INITIALIZED                              
       MOVE BIG TO TINY.    
       
       
       * --- ruleid : ok bof ---
       MOVE "ABCDEFGHIJKLMNOPQRST" TO SOURCE-FIELD
       IF FUNCTION LENGTH(SOURCE-FIELD) <= MAX-LEN
           MOVE SOURCE-FIELD(1:MAX-LEN) TO DEST-FIELD
       ELSE
           DISPLAY "Error: input too big"
       END-IF
       
       
       DISPLAY "Enter a long string (max 100 chars): ".
       * --- ruleid : ok bof ---
       ACCEPT LONG-INPUT
       IF FUNCTION LENGTH(LONG-INPUT) <= LENGTH OF SHORT-FIELD
       MOVE LONG-INPUT TO SHORT-FIELD.

       STOP RUN.
