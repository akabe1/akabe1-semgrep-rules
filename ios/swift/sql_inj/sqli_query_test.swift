import example


// Check SQL injection 
class SQLiViewController: ViewController {

    
    func foo1() {
        let queryString = "SELECT * FROM items WHERE owner='\(username)' AND itemname='\(item)'"
        var queryStatement: OpaquePointer? = nil
        if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK {
            if sqlite3_step(queryStatement) == SQLITE_ROW {
                println("SQL query done")
            }
        }
   }
   
   
   func foo2() {
        let query = concatString("((SELECT COUNT (*) "
            + "      FROM ASD_TABLE a1 "
            + "      WHERE a1.state = h1.row_id "
            + "      AND a1.code_loc = h1.loc "
            + "      AND SYSDATE BETWEEN a1.start_date AND a1.end_date "
            + "      AND a1.KEY = '" + keyDB + "') > 100 "
            + " OR (SELECT COUNT (*)"
            + "      FROM DSA_TABLE z1 "
            + "      WHERE z1.state = q1.row_id "
            + "      AND z1.code_loc = q1.loc "
            + "      AND SYSDATE BETWEEN z1.start_date AND z1.end_date "
            + "      AND z1.title = 'A Fistful of Dollars' "
            + "      AND z1.KEY = '" + keyDB + "') <= 100 ");
    }
   
  
  
  
    func foo3() {
        let queryString = "SELECT * FROM items WHERE owner=" + username + " AND (itemname=" + item +")"
        var queryStatement: OpaquePointer? = nil
        if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK {
            if sqlite3_step(queryStatement) == SQLITE_ROW {
                println("SQL query done")
            }
        }
   }  
   
   
   
   
   func foo4() {
       // no SQL Injection
       let info = "INFO" + tipology + "_KEY"
   } 



   func foo5() {
       let queryString = "SELECT * FROM items WHERE owner=" + username 
       var queryStatement: OpaquePointer? = nil
       if sqlite3_prepare_v2(db, queryString, -1, &queryStatement, nil) == SQLITE_OK {
           if sqlite3_step(queryStatement) == SQLITE_ROW {
               println("SQL query done")
           }
       }
   }   
   
   
   
   
}
