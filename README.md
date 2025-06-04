# YARAAI_skeleton



## pipeline 

```
input: 
json file  



"get_metadata"
    path, module, base, size, md5, sha256, crc32, filesize
      
"get_current_address" - 16진수

"file_entropy" - 실수

"string_stats"
    string_count, avg_str_len, max_str_len

functions

  { name - str
    address - int
    size - 16진수
    instr_count - int
    branch_count - int
    cyclomatic - int
    xref_count - int
    disassembly - 여러개의 str
    }
```

1. json file의 get_metadata, get_current_address, file_entropy, string_stats는 str 형태로 기본 프롬포트에 내부 값과 함께 삽입한다.  


2. functions의 경우 내부 요소를 파싱하여 .asm 확장자로 변환한다.  


3. 별도의 api(따로 지정해 배포한 assembly 전용 요약 프로젝트)를 이용하여 .asm확장자로 변환한 assembly에 대한 자연어 설명을 얻은 뒤 기본 프롬포트에 삽입한다.


4. openAI api를 호출하여 프롬포트의 내용을 통해 yara rule 생성을 요청한다.


5. api 응답 str에서 yara rule을 파싱한다.


6. yara rule 검증용 라이브러리로 해당 결과를 검증한다.


7. 프로젝트의 result 폴더에 해당 yara rule을 저장한다.