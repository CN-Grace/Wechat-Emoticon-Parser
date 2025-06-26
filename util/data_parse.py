import sqlite3
import os
import json
import requests


def get_corsor(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    return cursor


def get_emotion_data(cursor):
    sql_str = """
                SELECT *
                FROM (
                SELECT EmotionDes1.ProductId, EmotionDes1.Des, EmotionItem.Data
                FROM EmotionDes1, EmotionItem
                WHERE EmotionDes1.MD5 = EmotionItem.MD5)
                AS tab1,(
                SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS RowNum,
                EmotionPackageItem.Name
                FROM EmotionPackageItem) AS tab2
                WHERE tab1.ProductId = tab2.RowNum
            """
    cursor.execute(sql_str)
    result = cursor.fetchall()
    return result


def get_custom_emotion_data(cursor, save_path):
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    for table in tables:
        table_name = table[0]
        if "CustomEmotion" != table_name:
            continue
        # 获取表的所有数据
        cursor.execute(f"SELECT * FROM {table_name};")
        rows = cursor.fetchall()
        for idx, row in enumerate(rows):
            response = requests.get(row[2])
            if response.status_code == 200:
                with open(os.path.join(save_path, row[0] + ".gif"), "wb") as f:
                    f.write(response.content)
                print(f"Downloaded {idx}/{len(rows)} successfully")
            else:
                print(f"Failed to download {row[2]}")


def save_to_sys(result, save_path):
    for item in result:
        Des = item[1][6:].decode("utf-8")
        Data = item[2]
        Package = item[4]
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        Package_path = os.path.join(save_path, Package)
        if not os.path.exists(Package_path):
            os.makedirs(Package_path)
        try:
            with open(os.path.join(Package_path, Des + ".gif"), "wb+") as f:
                f.write(Data)
        except Exception as e:
            print(f"Error saving {Des}: {e}")

def parse():
    db_path = "./data/Emotion.db"
    cursor = get_corsor(db_path)
    result = get_emotion_data(cursor)
    save_path = "./Emotion"
    get_custom_emotion_data(cursor, os.path.join(save_path, "CustomEmotion"))
    save_to_sys(result, save_path)
