<<<<<<< HEAD
import matplotlib.pyplot as plt

def plot_email_categories(email_data):
    categories = {}
    for email in email_data:
        category = email['classification'].split(",")[0].strip()
        categories[category] = categories.get(category, 0) + 1
    plt.figure(figsize=(8, 6))
    plt.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%')
    plt.title("Email Categories")
    plt.show()
=======
��
>>>>>>> 4d56f5b5800e5ff2a07cfe61a5fdca460250fe87
