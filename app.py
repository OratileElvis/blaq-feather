from flask import Flask, render_template, request, redirect
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)

# Email configuration (Gmail SMTP setup)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Initialize Flask-Mail
mail = Mail(app)

@app.route('/')
def home():
    return render_template('index.html')  # Home page

@app.route('/about')
def about():
    return render_template('about.html')  # About page

@app.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')  # Portfolio page

@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if request.method == 'POST':
        # Collect form data
        name = request.form['name']
        phone = request.form['phone']
        date = request.form['date']
        message = request.form.get('message', '')
        
        # Create the email message
        msg = Message(
            'New Tattoo Booking Request',
            recipients=['blaqfeather115@gmail.com']
        )
        
        # Email body content
        msg.body = f"""
        You have a new booking request:

        Name: {name}
        Email: {phone}
        Preferred Date: {date}
        Message: {message}
        """
        
        try:
            mail.send(msg)
            return redirect('/thank-you')
        except Exception as e:
            print(f"Error sending email: {e}")
            return "There was an error sending the email."

    return render_template('booking.html')

@app.route('/thank-you')
def thank_you():
    return render_template('thank-you.html')  # Thank you page after form submission

@app.route('/testimonials')
def testimonials():
    return render_template('testimonials.html')  # Testimonials page

@app.route('/contact')
def contact():
    return render_template('contact.html')  # Contact page

if __name__ == "__main__":
    app.run(debug=True)
