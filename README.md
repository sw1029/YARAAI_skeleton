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
* `yara-python`을 이용한 오탐률 평가 로직 개선
```

## 사용 가이드
```bash
python preflight.py # 필요시 수행하는 명령어. api key를 arg로 받아 config.json을 생성한다.

python cli.py --test # api key, 실제 데이터 없이 파이프라인의 작동만 검증하는 명령어

python cli.py <path/to/your/executable_file> # 실행파일의 경로를 지정하여 파이프라인 구동

python cli.py <path/to/your/analysis.json> # json 형태로 전처리된 분석결과를 가져와서 파이프라인 구동

python cli.py <input_path> --openai_asm # 요약 task에 openai api를 임시로 사용 가능하게 설정해 놓았다. 추후 요약 파이프라인을 별도로 붙일 예정

python cli.py <input_path> --asm_api <your_api_url> # 추후 api 형태로 구현한 코드 요약 기능을 덧붙일 수 있다.
```

## 코드별 설명
```
cli.py
    메인 명령줄 인터페이스. 실행 파일, json의 경로를 입력받아 pipeline에 전달

pipeline.py
    json 을 기본 프롬포트로 변환 
    -> 어셈블리 코드를 요약하여 프롬포트에 추가
    -> openai API를 호출하여 yara rule 생성 요청
    -> 생성된 rule을 파싱 및 검증(최대 3번)
    -> 디버깅을 위해 rule 파싱 전의 응답을 별도로 저장
    -> 최종 YARA rule을 result 폴더에 저장

utils.py
    프로젝트 전반에서 사용되는 다용도 헬퍼 함수
        openai api 호출
        llm 결과값에서 yara rule 파싱
        룰의 문법 유효성 검증
        yara-python 라이브러리로 오탐률 검증(이 경우 benign samples 등의 폴더에 데이터가 들어있어야 한다)

data_maker.py
    json을 읽어 프롬포트로 변환
    디스어셈블 된 코드를 .asm 확장자로 변환하여 저장한다.
    
model.py
    openai api 호출의 wrapper 클래스
    
assembly_api.py
    코드 요약 api
        외부 api
            openai (--openai_asm 플래그)
            별도의 custom api (--asm_api)

config.py
    설정 및 api key 관리

preflight.py
    파이프라인 실행 전 사전실행 코드.
    api 키가 설정되지 않은 경우 입력받아 config.json에 저장
    테스트 모드로 파이프라인 점검 여부를 물은 후 간단한 점검 수행.
```

## 디렉토리별 설명
```
benign_samples
    오탐률을 탐지하기 위한 정상 샘플 보관

asm
    파이프라인이 실행될 때 data_maker에 의해 생성되는 디렉토리. 디스어셈블 결과값 저장.

result
    최종 yara rule 파일 저장

responses
    디버깅을 위하여 llm의 raw response를 저장
```