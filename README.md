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


3. 별도의 api(따로 지정해 배포한 assembly 전용 요약 프로젝트)를 이용하여 .asm확장자로 변환한 assembly에 대한 자연어 설명을 얻은 뒤 기본 프롬포트에 삽입한다. `--openai_asm` 플래그를 사용하면 OpenAI API를 이용해 요약한다.


4. openAI api를 호출하여 프롬포트의 내용을 통해 yara rule 생성을 요청한다.


5. api 응답 str에서 yara rule을 파싱한다.


6. yara rule 검증용 라이브러리로 해당 결과를 검증한다.


7. 프로젝트의 result 폴더에 해당 yara rule을 저장한다.


# 추가 구현 사항
```
CLI 구현
    1. 원본 실행파일(exe, dll)인지 json 파일인지에 따라 데이터 전처리를 다르게 하여 파이프라인에 데이터 삽입.
    2. 간단한 명령어를 통하여 파이프라인 제어
    3. 최종 결과물이 되는 yara rule의 오탐률을 `yara-python`으로 계산
    4. YARA rule 파싱 실패 시 최대 세 번까지 재시도하며 각 응답은 `responses/` 폴더에 저장

Api call
    1. openAI 인증키는 별도의 설정파일에서 관리
    2. 별도의 api(따로 지정해 배포한 assembly 전용 요약 프로젝트)는 인터페이스 형태로 추상화하여 부름. 이 때 요약 호출은 api 호출을 wrapping 하는 class를 선언하여 가시성을 높임
    3. `--openai_asm` 플래그를 사용하면 OpenAI API(gpt-4o)로 어셈블리 요약을 수행
```

### Test mode

`cli.py`에는 `--test` 플래그가 있어 API 키나 입력 파일이 없을 때 샘플 데이터(`sample.json`)로 파이프라인을 실행할 수 있다.

## TODO - 코드에서 미구현된 부분
```
* `preprocess_binary` 함수에 실제 실행파일 분석 로직 추가
* `yara-python`을 이용한 오탐률 평가 로직 개선
```
