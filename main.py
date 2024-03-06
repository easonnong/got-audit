import json
import os
import requests
import subprocess
import typer
from dotenv import load_dotenv

load_dotenv()

app = typer.Typer()

api_key = os.environ.get("OPENAI_API_KEY")

html_begin = '''
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Audit Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-800 text-white">
    <header class="p-4 shadow-lg bg-gray-900">
      <div class="container mx-auto">
        <h1 class="text-xl">Vulnerability Report</h1>
      </div>
    </header>

    <div class="container mx-auto my-4 p-4 bg-gray-900 rounded">
      <div class="grid grid-cols-1 md:grid-cols-1 lg:grid-cols-1 gap-4">

'''

html_body_begin = '''
        <div class="bg-gray-700 p-4 rounded">
          <h2 class="text-lg mb-2">{}</h2>
          <table>
            <tr>
              <th>Lines</th>
              <th>Description</th>
              <th>Action</th>
              <th>Severity</th>
              <th>Actors</th>
              <th>Scenario</th>
              <th>Type</th>
            </tr>
'''

html_body = '''
            <tr
              class="odd:bg-white odd:dark:bg-gray-900 even:bg-gray-50 even:dark:bg-gray-800 border-bottom:bg-gray-500"
            >
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
              <td class="align-top px-6 py-4" style="color: black;">{}</td>
            </tr>
'''

html_body_end = '''
          </table>
        </div>
'''

html_end = '''
      </div>
    </div>
  </body>
</html>
'''

def generate_html_report(html_report, gpt4_results, line_pre, file_path):  
    html_report_temp = html_report

    try:  
        choices = gpt4_results['choices']
        for choice in choices:
            message = choice['message']
            content = message['content']

            html_report_temp += html_body_begin.format(file_path)

            lines = content.splitlines()
            remaining_lines = lines[1:-1]
            vulnerabilities = "\n".join(remaining_lines)
            vulnerabilities_json = json.loads(vulnerabilities)

            for item in vulnerabilities_json:
                table = html_body.format(str(item['lines'][0] + line_pre), item['description'], item['action'], item['severity'], ', '.join(item['actors']), item['scenario'], item['type'])
                html_report_temp += table

            html_report_temp += html_body_end  
        html_report = html_report_temp      
    except Exception as e:
        error_message = f"File path:{file_path}, An error occurred: {str(e)}"
        with open('errors.log', 'a') as f:
            f.write(error_message)
    
    return html_report


def flatten_code(code_path):
    try:
        command = ['npx', 'truffle-flattener', code_path]
        flattened_code = subprocess.check_output(command)
        return flattened_code.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error flattening contract: {e}")
        return None


def generate_prompt(flattened_code):
    prompt = (
        "Provide an exhaustive list of all issues and vulnerabilities inside the following code. "
        "Be detailed in the issue descriptions and describe the actors involved. Include one exploit scenario "
        "in each vulnerability. Output as a valid JSON with a list of objects that each have 'lines', 'description', "
        "'action', 'severity', 'actors', 'scenario', and 'type'. 'lines' refers to the line numbers where the vulnerabilities are located, 'type' can be 'usability', 'vulnerability', "
        "'optimization', or 'suggestion'. 'actors' is a list of the involved actors. 'severity' can be "
        "'low + ice block emoji', 'medium', or 'high + fire emoji'. "
        "Output high severity findings first and low severity findings last.\n\n"
        "```\n" + flattened_code + "\n```\n\n"
    )
    return prompt


def process_code(prompt: str, html_report, line_pre, file_path):
    # Write the generated prompt to a file
    with open('llm_prompt.txt', 'w') as file:
        file.write(prompt)
    # print("Generated Prompt for LLM written to llm_prompt.txt")
    # print("AI code review in progress. This might take a while.")
    # print("...")

    gpt4_response = query_llm(prompt)
    # typer.echo("AI Analysis Results:")
    # typer.echo(gpt4_response)
    return generate_html_report(html_report, gpt4_response, line_pre, file_path)


def query_llm(prompt):
    try:
        url = "https://api.gptapi.us/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        response = requests.post(url, headers=headers, json=payload)
        return response.json()
    except Exception as e:
        print(f"Error querying GPT-4: {e}")
        return None


@app.command()
def flatten(code_path: str):
    """
    Flatten a code.
    """
    flattened_code = flatten_code(code_path)
    if flattened_code:
        typer.echo("Code successfully flattened.")
        typer.echo(flattened_code)
    else:
        typer.echo("Failed to flatten the code.")


@app.command()
def analyze(code_path: str):
    """
    Analyzing code for vulnerabilities.
    """

    html_report = html_begin

    print("Generated Prompt for LLM will written to llm_prompt.txt")
    print("Please open report.html in your browser.\n")
    
    for filename in os.listdir(code_path):
        file_path = os.path.join(code_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, "r") as file:
                print(f"Auditing {file_path}...")
                lines = []
                line_counter = 0
                line_pre = 0
                for line in file:
                    lines.append(line)
                    line_counter += 1
                    if line_counter == 300:
                        # Process the 300 lines of code as a single string
                        html_report = process_code(generate_prompt(''.join(lines)), html_report, line_pre, file_path)
                        # Reset the lines and line_counter variables for the next batch
                        lines = []
                        line_counter = 0
                        line_pre += 300
                # Process any remaining lines that are less than 300
                if lines:
                    html_report = process_code(generate_prompt(''.join(lines)), html_report, 0, file_path)

            with open('report.html', mode="w", encoding="utf-8") as message:
                message.write(html_report)

    with open(filename, mode="a", encoding="utf-8") as message:
        message.write(html_end)
    print(f"... wrote {filename}")


if __name__ == "__main__":
    app()