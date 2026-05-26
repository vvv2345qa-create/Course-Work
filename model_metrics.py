from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def calculate_confusion_matrix(results):
    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for row in results:
        predicted = bool(row["is_malicious"])
        actual = bool(row["true_label"])

        if predicted and actual:
            tp += 1
        elif not predicted and not actual:
            tn += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def calculate_classification_metrics(results):
    matrix = calculate_confusion_matrix(results)
    tp = matrix["tp"]
    tn = matrix["tn"]
    fp = matrix["fp"]
    fn = matrix["fn"]

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def create_confusion_matrix_plot(results, output_dir, filename="confusion_matrix.png", title="Confusion matrix"):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    metrics = calculate_classification_metrics(results)
    matrix_values = [
        [metrics["tn"], metrics["fp"]],
        [metrics["fn"], metrics["tp"]],
    ]

    fig, ax = plt.subplots(figsize=(6, 5))
    image = ax.imshow(matrix_values, cmap="Blues")
    plt.colorbar(image, ax=ax)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred normal", "Pred malicious"])
    ax.set_yticklabels(["True normal", "True malicious"])
    ax.set_title(title)

    for row_index, row in enumerate(matrix_values):
        for col_index, value in enumerate(row):
            ax.text(col_index, row_index, str(value), ha="center", va="center", color="black")

    fig.tight_layout()
    path = output_dir / filename
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def print_classification_metrics(results, title="metrics"):
    metrics = calculate_classification_metrics(results)
    print(title + ":")
    print(f"accuracy: {metrics['accuracy']:.4f}")
    print(f"precision: {metrics['precision']:.4f}")
    print(f"recall: {metrics['recall']:.4f}")
    print(f"f1_score: {metrics['f1_score']:.4f}")
    print(f"tp: {metrics['tp']}")
    print(f"tn: {metrics['tn']}")
    print(f"fp: {metrics['fp']}")
    print(f"fn: {metrics['fn']}")
