from gpt4all import GPT4All

def main():
  
    model = GPT4All("Meta-Llama-3-8B-Instruct.Q4_0")
    
 
    prompt = "What is the capital of France?"
    

    response = model.generate(prompt, max_tokens=15)
    
    print(f"Model response: {response}")

if __name__ == '__main__':
    main()
