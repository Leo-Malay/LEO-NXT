### LEO-NXT <Python-localDB>

# By Malay Bhavsar (LEO-Malay)

<p><b>Key Features:</b> Easy to Use, Portable, Secure, Requires Less Storage, Source code under 400 Lines :)</p>
<p>You may use it directly or integrate with your Python program.</p>
<p>Not yet for commercial use</p>
<p>Following steps will help you with the code</p>

<pre>
# Creating an instance.
ldb = LEO_NXT.leodb("give path", "Username", "Password")

# Creating and fetching database
ldb.create_db("db_name")
ldb.get_db("db_name")

# Destroying the database.
ldb.destroy_db("db_name")

# Creating and fetching table.
ldb.create("table_name", ["col_name0", "col_name1"])
ldb.get_table("table_name")

# Inseting the record.
data_str = "col_name::value;;col_name::value;;col_name::value;;"
ldb.insert(data_str)

# Search the record.
ldb.search("")   # -> Returns all the records
ldb.search("name::Urja;;")   # -> Returns the matching records

# Update matching record.
search_str = "col_name::value;;"
value_str = "col_name::new_value;;"
ldb.update(search_str, value_str)

# Delete the matching record
ldb.delete("col_name::value;;")

# To save all the changes made and close the db
ldb.end()
</pre>
