from .connection import get_connection
from typing import Union
from pydantic import BaseModel

class User(BaseModel):
    user_id: int
    username: str
    full_name: str
    email: str 
    hashed_password: str


######################## FETCHING FUNC ################################
def fetch_all(query: str) -> dict:
    conn = get_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        print(f"Query error: {e}")
        return []
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()


def fetch_hashed_password(identifier: Union[str, int], is_username: bool=True) -> Union[str, bool]:
    if is_username:
        query = f'SELECT hashed_password FROM users WHERE username="{identifier}"'
        data = fetch_all(query)
        if data:
            return data[0]['hashed_password']
        else:
            return False
    else:
        query = f'SELECT hashed_password FROM users WHERE user_id="{identifier}"'
        data = fetch_all(query)
        if data:
            return data[0]['hashed_password']
        else:
            return False
    
    
def fetch_email(identifier: Union[str, int], is_username: bool=True) -> Union[str, bool]:
    if is_username:
        query = f'SELECT email FROM users WHERE username="{identifier}"'
        data = fetch_all(query)
        if data:
            return data[0]['email']
        else:
            return False
    else:
        query = f'SELECT email FROM users WHERE user_id="{identifier}"'
        data = fetch_all(query)
        if data:
            return data[0]['email']
        else:
            return False

def fetch_user_info(identifier: Union[str, int], is_username: bool=True) -> Union[User, bool]:
    if is_username:
        query = f'SELECT * FROM users WHERE username="{identifier}"'
        data = fetch_all(query)
        if data:
            return User(**data[0])
        else:
            return False
    else:
        query = f'SELECT * FROM users WHERE user_id="{identifier}"'
        data = fetch_all(query)
        if data:
            return User(**data[0])
        else:
            return False

########################## INSERT FUNC #################################
def insert_user(user: User) -> bool:
    conn = get_connection()
    if not conn:
        print("Failed to get database connection.")
        return False

    query = """
    INSERT INTO users (username, full_name, email, hashed_password)
    VALUES (%s, %s, %s, %s);
    """

    data_tuple = (
        user.username,
        user.full_name,
        user.email,
        user.hashed_password
    )

    try:
        cursor = conn.cursor()
        cursor.execute(query, data_tuple)
        conn.commit()
        print("User inserted successfully!")
        return True
    except Exception as e:
        print(f"Error inserting user: {e}")
        conn.rollback()
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()


########################## UPDATE FUNC ####################################
# def update_email(identifier: Union[str, int], is_username: bool = True) -> bool:
#     if is_username:

#     return None