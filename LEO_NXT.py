# Importing modules.
from os import path, remove
from sys import stdout
from base64 import urlsafe_b64encode
from hashlib import sha512, sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class leodb:
    # This class serves the purpose of basic operations on the data
    def __init__(self, path, username, password):
        self.username = username
        self.password = password
        self.path = path
        self.db_name = ""
        self.data = -1
        self.table_index = -1
        self.table_data = ""
        self.db_io = db_io(self.path, self.username, self.password)

    def end(self):
        # This function serves the purpose of saving all the operation done.
        if self.table_index != -1:
            self.data[self.table_index] = self.table_data
        self.db_io.write_db(self.data)
        self.data = -1
        self.table_index = -1
        self.table_data = ""

    def get_db(self, db_name):
        # This function serves the purpose of fetching the DB.
        if self.table_index != -1:
            self.end()
        result = self.db_io.get_db(db_name)
        if result == True:
            success, self.data = self.db_io.read_db(db_name)
            if success == 0 or success == 1:
                return 1
            return -1
        else:
            return -1

    def get_table(self, table_name):
        # This function serves the purpose of fetching the Table
        for sub_data in self.data:
            if sub_data == []:
                pass
            elif sub_data[0] == table_name.lower():
                self.table_index = self.data.index(sub_data)
                self.table_data = self.data[self.table_index]
                break
        if self.table_index == -1:
            return -1
        return 1

    def create_db(self, db_name):
        # This function serves the purpose of creating a new DB.
        result, success = self.db_io.create_db(db_name)
        if result == -1 and success == True:
            stdout.write("[WARN]: db already exists\n")
            return 0
        if result == 1 and success == True:
            stdout.write("[LOG]: db created Successfully\n")
            return 1
        if result == -1 and success == False:
            stdout.write("[ERROR]: db was not created\n")
            return -1

    def destroy_db(self, db_name):
        # This function serves the purpose of deleting an existing DB.
        result = self.db_io.destroy_db(db_name)
        if result == -1:
            stdout.write("[ERROR]: db not found!\n")
            return -1
        if result == 1:
            stdout.write("[ERROR]: db destroyed successfully\n")
            return 1

    def create(self, table_name, col_list):
        # This function serves the purpose of creating new db
        if self.data == -1:
            stdout.write(
                "[ERROR]: No database selected. Try --> '.get_db()'\n")
            return -1
        for subdata in self.data:
            if subdata[0] == table_name.lower():
                stdout.write("[ERROR]: Table already exist!\n")
                return -1
        col_list = [col_name.lower() for col_name in col_list]
        self.data.append([table_name.lower(), col_list, []])
        return 1

    def destroy(self, table_name):
        # This function serves the purpose of deleting the db
        if self.data == -1:
            stdout.write(
                "[ERROR]: No database selected. Try --> '.get_db()'\n")
            return -1
        index = -1
        for subdata in self.data:
            if subdata[0] == table_name.lower():
                index = self.data.index(subdata)
        if index == -1:
            stdout.write("[ERROR]: No such table found\n")
            return -1
        else:
            if index < self.table_index:
                self.table_index -= 1
            elif index == self.table_index:
                self.table_index = -1
                self.table_data = ""
            self.data.pop(index)
            return 1

    def insert(self, data):
        # This function is used for inserting the record to the table.
        if self.data == []:
            return -1
        # Processing data given as input.
        success, in_col_ls, in_data_ls = self.process_input_data(data)
        if success != 1:
            return -1
        # Processing data from the disk.
        ds_col_list = self.table_data[1]
        ds_data_list = self.table_data[2]
        while "" in ds_data_list:
            ds_data_list.pop(ds_data_list.index(""))
        # Inserting the data.
        record_ls = []
        for col in ds_col_list:
            if col in in_col_ls:
                record_ls.append(in_data_ls[in_col_ls.index(col)])
            else:
                record_ls.append("NULL")
        record_ls = self.__list_to_string(record_ls, "%#%")
        ds_data_list.append(record_ls)
        self.table_data[2] = ds_data_list
        return 1

    def search(self, data, option=0):
        # This function is used to Search specific entries form the table.
        if self.data == []:
            return -1
        # Processing data given as input.
        success, in_col_ls, in_data_ls = self.process_input_data(data)
        if success != 1:
            return -1
        # Processing data from the disk.
        ds_col_list = self.table_data[1]
        ds_data_list = self.table_data[2]
        while "" in ds_data_list:
            ds_data_list.pop(ds_data_list.index(""))
        # Generating the output.
        if data == "":
            new_return_ls = [ds_col_list]
            for record in ds_data_list:
                new_return_ls.append(self.__string_to_list(record, "%#%"))
            return new_return_ls
        return_ls = []
        for i in range(len(ds_data_list)):
            count = 0
            for col in in_col_ls:
                nn_data = self.__string_to_list(ds_data_list[i], "%#%")
                if col in ds_col_list:
                    if nn_data[ds_col_list.index(col)] == in_data_ls[in_col_ls.index(col)]:
                        count += 1
            if count == len(in_col_ls):
                return_ls.append(ds_data_list[i])
        if option == 1:
            self.search_result = return_ls
            return 1
        elif option == 0:
            new_return_ls = [ds_col_list]
            for record in return_ls:
                new_return_ls.append(self.__string_to_list(record, "%#%"))
            return new_return_ls

    def delete(self, data):
        # Deletes the data from table searched using provided data..
        if self.data == []:
            return -1
        success = self.search(data, 1)
        if success != 1:
            return -1
        # Processing data from the disk.
        ds_col_list = self.table_data[1]
        ds_data_list = self.table_data[2]
        while "" in ds_data_list:
            ds_data_list.pop(ds_data_list.index(""))
        for value in self.search_result:
            if value in ds_data_list:
                ds_data_list.pop(ds_data_list.index(value))
        self.table_data[2] = ds_data_list

    def update(self, search_ls, value_ls):
        # Search old data and replace the new values with the old once.
        if self.data == []:
            return -1
        success = self.search(search_ls, 1)
        if success != 1:
            return -1
        # Processing data given as input.
        success, in_col_ls, in_data_ls = self.process_input_data(value_ls)
        if success != 1:
            return -1
        # Processing data from the disk.
        ds_col_list = self.table_data[1]
        ds_data_list = self.table_data[2]
        while "" in ds_data_list:
            ds_data_list.pop(ds_data_list.index(""))
        # preparing the new_list.
        for i in range(len(self.search_result)):
            for col in in_col_ls:
                if col in ds_col_list:
                    nn_data = ds_data_list[ds_data_list.index(
                        self.search_result[i])]
                    nn_data = self.__string_to_list(nn_data, "%#%")
                    nn_data[ds_col_list.index(
                        col)] = in_data_ls[in_col_ls.index(col)]
                    nn_data = self.__list_to_string(nn_data, "%#%")
                    ds_data_list[ds_data_list.index(
                        self.search_result[i])] = nn_data
        self.table_data[2] = ds_data_list

    def process_input_data(self, data):
        # This function serves the purpose of processing the input data.
        data = self.__string_to_list(data, ";;")
        pro_data_ls = []
        pro_col_ls = []
        for subdata in data:
            if subdata != "":
                new_data = self.__string_to_list(subdata, "::")
                if len(new_data) != 2:
                    stdout.write("[ERROR]: Invalid data input!\n")
                    return -1, [], []
                pro_col_ls.append(new_data[0])
                pro_data_ls.append(new_data[1])
        return 1, pro_col_ls, pro_data_ls

    def __list_to_string(self, data, join_with=""):
        # This function convert list to string.
        return join_with.join(element for element in data)

    def __string_to_list(self, data, split_with=" "):
        # This function convert string to list.
        data_ls = data.split(split_with)
        return [element.strip() for element in data_ls]


class db_security:
    # This class serves purpose of Encrypting & Decrypting the data.
    def __init__(self, password):
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt="None Of Your Business Fucker".encode(),
            iterations=100000,
        )
        key = urlsafe_b64encode(kdf.derive(password.encode()))
        self.crypt_obj = Fernet(key)

    def e_crypt(self, data):
        # Function serves the purpose of Encrypting the data.
        data = self.crypt_obj.encrypt(data.encode())
        return data.decode()

    def d_crypt(self, data):
        # Function serves the purpose of Decrypting the data.
        data = self.crypt_obj.decrypt(data.encode())
        return data.decode()

    def gen_hash(self, data):
        # Function serves the purpose of hashing the data.
        hash_data = sha512(data.encode())
        d_hash_data = sha256(hash_data.hexdigest().encode())
        return d_hash_data.hexdigest()


class db_io:
    # This class serves purpose of Reading & Writing,Too & Fro from the storage.
    def __init__(self, root_path, username, password):
        self.root_path = f"{root_path}"
        self.username = username
        self.security = db_security(password)
        self.db_path = ""

    def __gen_db_name(self, db_name):
        self.db_path = self.root_path + \
            self.security.gen_hash(db_name+self.username) + ".leoDB"
        if path.exists(self.db_path):
            return True
        else:
            return False

    def create_db(self, db_name):
        # This function serves the purpose of selectng te database.
        success = self.__gen_db_name(db_name)
        if success == True:
            return -1, True
        else:
            result = self.write_db("")
            if result == 0:
                return 1, True
            return -1, False

    def destroy_db(self, db_name):
        # This function serves the purpose of selectng te database.
        success = self.__gen_db_name(db_name)
        if success == True:
            remove(self.db_path)
            self.db_path = ""
            return 1
        else:
            return 0

    def get_db(self, db_name):
        # This function serves the purpose of selectng te database.
        return self.__gen_db_name(db_name)

    def read_db(self, db_name):
        # This function serves the purpose of reading and decrypting the data.
        db_file = open(self.db_path, "r")
        db_data = db_file.read()
        db_file.close()
        if len(db_data) == 0:
            return 0, []
        else:
            try:
                db_data = self.security.d_crypt(db_data)
                db_data = self.__extract_data(db_data)
                return 1, db_data
            except:
                stdout.write("[ERROR]: No such db exist. Try creating one.\n")
                return -1, []

    def write_db(self, data):
        # This function serves the purpose of encrypting and writing the data.
        if len(data) == 0:
            db_file = open(self.db_path, "w")
            db_file.close()
            return 0
        db_data = self.__deploy_data(data)
        db_data = self.security.e_crypt(db_data)
        db_file = open(self.db_path, "w")
        db_file.write(db_data)
        db_file.close()
        return 1

    def __extract_data(self, data):
        # This function serves the purpose of extracting data.
        data = [x.strip() for x in data.split("(_#_)")]
        data.pop()
        data_ls = []
        for subls in data:
            new_data = []
            data = [x.strip() for x in subls.split("(#)")]
            sub_1 = [x.strip() for x in data[1].split("_#_")]
            sub_2 = [x.strip() for x in data[2].split("_#_")]
            new_data.append(data[0])
            new_data.append(sub_1)
            new_data.append(sub_2)
            data_ls.append(new_data)
        return data_ls

    def __deploy_data(self, data):
        # This function serves the purpose of deploying data.
        new_data = []
        while "" in data:
            data.pop(data.index(""))
        for subdata in data:
            data_a = []
            subdata_1 = "_#_".join(subdata[1])
            subdata_2 = "_#_".join(subdata[2])
            data_a.append(subdata[0])
            data_a.append(subdata_1)
            data_a.append(subdata_2)
            new_data.append("(#)".join(data_a))
        new_data = "(_#_)".join(new_data) + "(_#_)"
        return new_data
