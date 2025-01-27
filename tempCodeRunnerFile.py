@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    money_request = MoneyRequest.query.get_or_404(request_id)
    if money_request.recipient != current_user:
        return jsonify({'success': False, 'message': 'Unauthorized request.'}), 403

    if money_request.status == 'pending':
        if current_user.balance < money_request.amount:
            return jsonify({'success': False, 'message': 'Insufficient funds to approve the request.'}), 400
        else:
            try:
                current_user.balance -= money_request.amount
                money_request.sender.balance += money_request.amount
                money_request.status = 'approved'
                debit_transaction = Transaction(user_id=current_user.id, amount=money_request.amount, type='debit', remarks=money_request.remarks)
                credit_transaction = Transaction(user_id=money_request.sender.id, amount=money_request.amount, type='credit', remarks=money_request.remarks)
                db.session.add(debit_transaction)
                db.session.add(credit_transaction)
                transfer = Transfer(debit_transaction_id=debit_transaction.id, credit_transaction_id=credit_transaction.id)
                db.session.add(transfer)
                db.session.commit()
                flash('Request approved.', 'success')
                return jsonify({'success': True, 'message': 'Request approved.'})
            except Exception as e:
                db.session.rollback()
                return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 400

    return jsonify({'success': False, 'message': 'Request not pending.'}), 400