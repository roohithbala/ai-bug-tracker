import google.generativeai as genai

genai.configure(api_key="AIzaSyBaZi_KWgbCr2tmbCLjSdD2ZZsQKbnkBYs")

response = genai.GenerativeModel("gemini-2.0-flash").generate_content(
    "Write a story about a magic backpack."
)

print(response.text)
