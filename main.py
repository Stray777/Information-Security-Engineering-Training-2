from view import View
from controller import Controller


def main():
    view = View()
    controller = Controller(view)
    controller.run_view()


if __name__ == "__main__":
    main()
