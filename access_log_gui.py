from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from access_log_features import (
    BAD_TEST_IP_PATH,
    BAD_TRAIN_IP_PATH,
    GOOD_TEST_IP_PATH,
    GOOD_TRAIN_IP_PATH,
    IsolationForest,
    MODEL_PATH,
    OUTPUT_DIR,
    TEST_PATH,
    TRAIN_PATH,
    calculate_accuracy,
    predict_with_saved_model,
    save_results_to_csv,
    train_isolation_model,
)


def create_accuracy_figure(train_accuracy, test_accuracy):
    fig = Figure(figsize=(5, 3.2), dpi=100)
    ax = fig.add_subplot(111)
    labels = ["train", "test"]
    values = [train_accuracy, test_accuracy]
    bars = ax.bar(labels, values, color=["#4c78a8", "#f58518"])
    ax.set_ylim(0, 1)
    ax.set_ylabel("accuracy")
    ax.set_title("Accuracy")

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            min(value + 0.03, 0.98),
            f"{value:.2%}",
            ha="center",
        )

    fig.tight_layout()
    return fig


def create_anomaly_figure(results, title="Test IP anomaly score"):
    fig = Figure(figsize=(7, 3.5), dpi=100)
    ax = fig.add_subplot(111)
    top_results = sorted(results, key=lambda row: row["isolation_score"], reverse=True)[:15]
    ips = [row["ip"] for row in top_results]
    scores = [row["isolation_score"] for row in top_results]
    colors = ["#c73e3a" if row["is_malicious"] else "#4c78a8" for row in top_results]

    ax.bar(ips, scores, color=colors)
    ax.set_title(title)
    ax.set_xlabel("ip")
    ax.set_ylabel("anomaly score")
    ax.tick_params(axis="x", rotation=60)
    fig.tight_layout()
    return fig


class AccessLogApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Apache access.log anomaly detector")
        self.root.geometry("1180x760")

        self.train_results = []
        self.test_results = []
        self.train_scores = None
        self.test_scores = None
        self.figure_canvases = []

        self.status = tk.StringVar(value=self.initial_status())
        self.train_accuracy_var = tk.StringVar(value="Train accuracy: -")
        self.test_accuracy_var = tk.StringVar(value="Test accuracy: -")
        self.model_path_var = tk.StringVar(value=str(MODEL_PATH))
        self.train_path_var = tk.StringVar(value=str(TRAIN_PATH))
        self.test_path_var = tk.StringVar(value=str(TEST_PATH))

        self.build_layout()

    def initial_status(self):
        if Path(MODEL_PATH).exists():
            return "Saved model found. Load a test access.log file."
        return "Saved model not found. Train the model first."

    def build_layout(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Train file:").grid(row=0, column=0, sticky="w")
        ttk.Label(top, textvariable=self.train_path_var).grid(row=0, column=1, sticky="w")
        ttk.Label(top, text="Model file:").grid(row=1, column=0, sticky="w")
        ttk.Label(top, textvariable=self.model_path_var).grid(row=1, column=1, sticky="w")
        ttk.Label(top, text="Test file:").grid(row=2, column=0, sticky="w")
        ttk.Label(top, textvariable=self.test_path_var).grid(row=2, column=1, sticky="w")

        buttons = ttk.Frame(top)
        buttons.grid(row=0, column=2, rowspan=3, padx=20, sticky="e")
        ttk.Button(buttons, text="Train / retrain model", command=self.train_model).pack(fill="x", pady=2)
        ttk.Button(buttons, text="Load test log", command=self.choose_test_file).pack(fill="x", pady=2)
        ttk.Button(buttons, text="Run TEST_PATH", command=lambda: self.run_test(Path(self.test_path_var.get()))).pack(fill="x", pady=2)

        ttk.Label(top, textvariable=self.status).grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(top, textvariable=self.train_accuracy_var).grid(row=4, column=0, sticky="w")
        ttk.Label(top, textvariable=self.test_accuracy_var).grid(row=4, column=1, sticky="w")
        top.columnconfigure(1, weight=1)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.malicious_frame = ttk.Frame(notebook)
        self.legit_frame = ttk.Frame(notebook)
        self.graph_frame = ttk.Frame(notebook)
        notebook.add(self.malicious_frame, text="Malicious IPs")
        notebook.add(self.legit_frame, text="Legitimate IPs")
        notebook.add(self.graph_frame, text="Charts")

        self.malicious_tree = self.create_tree(self.malicious_frame)
        self.legit_tree = self.create_tree(self.legit_frame)

    def create_tree(self, parent):
        columns = ("ip", "requests", "score", "true_label", "correct", "reason")
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        headings = {
            "ip": "IP",
            "requests": "Requests",
            "score": "Anomaly score",
            "true_label": "True label",
            "correct": "Correct",
            "reason": "Reason",
        }
        widths = {
            "ip": 140,
            "requests": 80,
            "score": 120,
            "true_label": 90,
            "correct": 80,
            "reason": 600,
        }

        for column in columns:
            tree.heading(column, text=headings[column])
            tree.column(column, width=widths[column], anchor="w")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    def train_model(self):
        if IsolationForest is None:
            messagebox.showerror("Error", "Install scikit-learn first: pip install scikit-learn")
            return False

        train_path = Path(self.train_path_var.get())
        if not train_path.exists():
            messagebox.showerror("Error", f"Training file not found:\n{train_path}")
            return False

        self.status.set("Training model...")
        self.root.update_idletasks()

        try:
            model_state, train_results, train_scores, saved_model_path = train_isolation_model(
                train_path,
                model_path=Path(self.model_path_var.get()),
                good_ip_path=GOOD_TRAIN_IP_PATH,
                bad_ip_path=BAD_TRAIN_IP_PATH,
            )
        except Exception as exc:
            messagebox.showerror("Training error", str(exc))
            self.status.set("Training failed")
            return False

        self.train_results = train_results
        self.train_scores = train_scores
        self.model_path_var.set(str(saved_model_path))
        self.train_accuracy_var.set(f"Train accuracy: {calculate_accuracy(train_results):.2%}")
        self.status.set("Model trained and saved")
        return True

    def choose_test_file(self):
        path = filedialog.askopenfilename(
            title="Choose test access.log",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if path:
            self.test_path_var.set(path)
            self.run_test(Path(path))

    def run_test(self, test_path):
        if IsolationForest is None:
            messagebox.showerror("Error", "Install scikit-learn first: pip install scikit-learn")
            return

        model_path = Path(self.model_path_var.get())
        if not model_path.exists():
            if not self.train_model():
                return

        if not test_path.exists():
            messagebox.showerror("Error", f"Test file not found:\n{test_path}")
            return

        if not self.train_results:
            train_path = Path(self.train_path_var.get())
            if train_path.exists():
                self.train_model()

        self.status.set("Checking test sample...")
        self.root.update_idletasks()

        try:
            model_state, test_results, test_scores = predict_with_saved_model(
                test_path,
                model_path=model_path,
                good_ip_path=GOOD_TEST_IP_PATH,
                bad_ip_path=BAD_TEST_IP_PATH,
            )
        except Exception as exc:
            messagebox.showerror("Prediction error", str(exc))
            self.status.set("Prediction failed")
            return

        self.test_results = test_results
        self.test_scores = test_scores
        self.test_accuracy_var.set(f"Test accuracy: {calculate_accuracy(test_results):.2%}")
        save_results_to_csv(test_results, output_dir=OUTPUT_DIR, filename="gui_test_malicious_ip_report.csv")
        self.fill_tables(test_results)
        self.draw_graphs()
        self.status.set("Test sample checked")

    def fill_tables(self, results):
        for tree in (self.malicious_tree, self.legit_tree):
            for item in tree.get_children():
                tree.delete(item)

        for row in results:
            values = (
                row["ip"],
                row["requests"],
                f"{row['isolation_score']:.4f}",
                row["true_label"],
                row["is_correct"],
                row["reason"],
            )
            if row["is_malicious"]:
                self.malicious_tree.insert("", "end", values=values)
            else:
                self.legit_tree.insert("", "end", values=values)

    def clear_graphs(self):
        for canvas in self.figure_canvases:
            canvas.get_tk_widget().destroy()
        self.figure_canvases.clear()
        for widget in self.graph_frame.winfo_children():
            widget.destroy()

    def add_figure(self, fig, row, column):
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        widget = canvas.get_tk_widget()
        widget.grid(row=row, column=column, sticky="nsew", padx=8, pady=8)
        self.figure_canvases.append(canvas)

    def draw_graphs(self):
        self.clear_graphs()
        self.graph_frame.columnconfigure(0, weight=1)
        self.graph_frame.columnconfigure(1, weight=1)
        self.graph_frame.rowconfigure(0, weight=1)

        train_accuracy = calculate_accuracy(self.train_results)
        test_accuracy = calculate_accuracy(self.test_results)
        accuracy_fig = create_accuracy_figure(train_accuracy, test_accuracy)
        anomaly_fig = create_anomaly_figure(self.test_results)

        self.add_figure(accuracy_fig, 0, 0)
        self.add_figure(anomaly_fig, 0, 1)


def main():
    root = tk.Tk()
    AccessLogApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
