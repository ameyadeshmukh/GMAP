from state import PenTestState
from graph import build_graph


def main():
    """
    Entry point of the system. invokes the graph and starts everything up
    """
    target = "TARGET_IP"
    state = PenTestState(target)
    graph = build_graph()
    graph.invoke(state)


if __name__ == "__main__":
    main()