import datetime

DEBUG = True
QUIET = False


class Log:
    NO_COLOR = False
    LOG_IN_FILE = False
    FILE = None

    @classmethod
    def set_nocolor_policy(cls, no_color):
        cls.NO_COLOR = no_color

    def debug(self, msg: str) -> None:
        if DEBUG and not QUIET:
            time = datetime.datetime.now()
            print("{}: {}".format(time, msg))

    @classmethod
    def set_file(cls, filename):
        cls.LOG_IN_FILE = True
        cls.FILE = open(filename, "a")

    @classmethod
    def print_cms(cls, type, msg, msg_default, level, no_color=None):
        # Define color for output
        DEFAULT = "\033[0m"
        BLUE = "\033[34m"
        GREEN = "\033[92m"
        YELLOW = "\033[33m"
        RED = "\033[91m"

        if no_color is None:
            no_color = cls.NO_COLOR

        formated_msg = ""
        NEEDED_COLOR = ""
        
        if no_color:
            formated_msg = "\t" * level + msg + msg_default

        else:
            if type == "default":
                NEEDED_COLOR = DEFAULT
            elif type == "info":
                NEEDED_COLOR = BLUE
            elif type == "good":
                NEEDED_COLOR = GREEN
            elif type == "warning":
                NEEDED_COLOR = YELLOW
            elif type == "alert":
                NEEDED_COLOR = RED
            else:
                NEEDED_COLOR = DEFAULT
            
            formated_msg = NEEDED_COLOR + "\t" * level + msg + DEFAULT + msg_default

        print(formated_msg)

        if cls.FILE:
            print(formated_msg, file=cls.FILE)

LOGGER = Log()
