import os
import sys

def increase_file_sizes(path, index):
    for item in os.listdir(path):
        item_path = os.path.join(path, item)
        if os.path.isfile(item_path):
            # 如果是文件，增加文件大小的10%
            original_size = os.path.getsize(item_path)
            new_size = int(original_size * 1.1)
            print("[handel] {}: {:5.4}MB -> {:5.4}MB".format(path, original_size/(1024**2), new_size/(1024**2)))
            with open(item_path, 'a') as f:
                f.write("\n")
                while original_size < new_size:
                    f.write(f"这是测试内容 this is test content *{index}* \n")
                    original_size = os.path.getsize(item_path)
                
        elif os.path.isdir(item_path):
            # 如果是文件夹，递归调用自身
            increase_file_sizes(item_path, index)

if __name__ == "__main__":
    file_path = sys.argv[1]
    file_index = sys.argv[2]
    increase_file_sizes(file_path, file_index)