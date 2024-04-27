import random
import time
import os
import datetime

mount_path = os.getenv('MOUNT_PATH')
if mount_path[-1] != "/":
    mount_path += "/"

def generate_random_number(length: int) -> int:
    return random.randint(1, length)

def return_time_stamp() -> str:
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def write_to_file(filepath: str, to_append: bool) -> None:
    write_mode = 'w'
    write_mode = 'a' if to_append is True else 'w'
    for _ in range(generate_random_number(4)):
        file = open(filepath, write_mode)
        file.write(return_time_stamp())
        file.write("\n")
        file.close()
        to_append = True
        write_mode = 'a' if to_append is True else 'w'
    return None

def main():
    while True:
        if generate_random_number(100) % 2 == 0:
            # case to write a file
            rand_num = generate_random_number(1000)
            file_path = mount_path + str(rand_num) + ".txt"
            append = False
            if os.path.exists(file_path):
                append = True
            write_to_file(file_path, to_append=append)
        else:
            # case to read from file
            files = [f for f in os.listdir(mount_path) if os.path.isfile(os.path.join(mount_path, f))]
            if files:
                for _ in range(generate_random_number(15)):
                    file_to_read = random.choice(files)
                    with open(os.path.join(mount_path, file_to_read), 'r') as f:
                        content = f.read()
        time.sleep(3)

if __name__ == "__main__":
    main()