# this script creat target table 
import sqlite3

#url = 'https://example.com/products.php'
#method = 'GET'
#params = "{'category': 'electronics', 'sort': 'price'}"
#headers = "{}"


con = sqlite3.connect("./Database/target.db")
cur = con.cursor()

# create table 
# cur.execute("CREATE TABLE target(url TEXT,method TEXT,query_params TEXT,body_params TEXT)")

# insert in table 
#sql_command = "INSERT INTO target VALUES(?, ?, ?, ?)"
#data_tuple = (url, method, params, headers)
# cur.execute(sql_command,data_tuple)

# read data 
cur.execute('SELECT * FROM target')
print(cur.fetchone())
con.commit()
con.close()