# PayWise | Secure Banking App

PayWise is a comprehensive financial management application built using Flask. The application allows users to manage their transactions, categorize expenses, receive personalized financial suggestions, visualize financial insights, and much more. We are continually working on it to make it more efficient and user-friendly.

## Features

1. **Transactional Data Management**:
    - Store transactions in SQLite database.
    - Each transaction includes amount, remark, timestamp, and category.
    - Automatically categorize transactions based on keywords in remarks.
    - Transactions without remarks are categorized as Miscellaneous.

2. **Categorization**:
    - Automatically categorize transactions.
    - Allow users to manually recategorize transactions.
    - Store custom category mappings for better accuracy over time.

3. **Financial Suggestions**:
    - Analyze transaction data to generate personalized financial suggestions.
    - Examples: "Your dining expenses are 30% of your income. Reduce eating out to save more."

4. **Graphical Insights**:
    - Provide visualizations such as bar charts, line charts, pie charts, and histograms.
    - Use Matplotlib, Plotly, or Seaborn for creating interactive and dynamic graphs.

5. **Account Summary**:
    - Display total income, total expenses, and net balance.
    - Monthly breakdown of income and expenses.
    - Alerts for low balances or overspending in a category.

6. **User Customization**:
    - Allow users to set monthly budgets by category.
    - Receive alerts when spending exceeds the budget.
    - Download transaction summaries in PDF or Excel format.

7. **Additional Features**:
    - Integrate Natural Language Processing (NLP) to understand and categorize transactions with vague remarks.
    - Add a chatbot interface for financial queries.
    - Ensure secure data handling with user authentication (e.g., Flask-Login).

8. **Performance and Scalability**:
    - Optimize SQLite queries for large datasets.
    - Ensure smooth integration of analysis and graphing functions with Flask routes.
    - Allow for future integration with external APIs (e.g., OpenAI for chat, external budgeting tools).

## Installation

To get started with the application, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/paywise-secure-banking-app.git
    cd paywise-secure-banking-app
    ```

2. **Create a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables**:
    - Create a `.env` file in the root directory and add the following:
    ```plaintext
    SECRET_KEY=your_secret_key
    SQLALCHEMY_DATABASE_URI=sqlite:///bank.db
    GOOGLE_APPLICATION_CREDENTIALS=path/to/your/service-account-file.json
    OPENAI_API_KEY=your_openai_api_key
    ```

5. **Initialize the database**:
    ```bash
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
    ```

6. **Run the application**:
    ```bash
    flask run
    ```

## Usage

- Register a new account.
- Log in with your account.
- Add, view, and manage your transactions.
- View financial insights and receive personalized suggestions.
- Set budgets and monitor your spending.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions or feedback, please contact [vvksrmacse@gmail.com].

---

**Note**: Replace placeholders like `yourusername`, `your_secret_key`, `path/to/your/service-account-file.json`, and `your_openai_api_key` with your actual details.

---

**Status**: We are still working on it to make it more efficient and user-friendly. Stay tuned for more updates!
