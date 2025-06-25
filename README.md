# designathon-ollama-cicd

### Requirements
1. Download [Ollama](https://ollama.com/download/windows)
2. Install `codellama` model
   ```shell
   ollama pull codellama
   ```
3. Python (version 3.10 or later)

### How to run
1. Clone this Repo and go to the root dir
2. Install the requirements
   ```shell
   pip install -r requirements.txt
   ```
4. Choose a Java project / cloned github repo and copy their path
5. Paste the path in the `bug_fixer.py` in the `main` function.
6. Run
   ```shell
   python bug_fixer.py
   ```
