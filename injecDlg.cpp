
// injecDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "injec.h"
#include "injecDlg.h"
#include "afxdialogex.h"
#include <tlhelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CinjecDlg 对话框



CinjecDlg::CinjecDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_INJEC_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CinjecDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CinjecDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CinjecDlg::OnBnClickedOk)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


// CinjecDlg 消息处理程序

BOOL CinjecDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	SetDlgItemText(IDC_EDIT2, "explorer.exe");
	

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CinjecDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CinjecDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CinjecDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CinjecDlg::OnDropFiles(HDROP hDropInfo)
{
	char filePath[MAX_PATH] = { 0 };
	UINT count = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);//从成功的拖放操作中检索文件的名称,并取代被拖拽文件的数目
	if (count == 1) {
		DragQueryFile(hDropInfo, 0, filePath, MAX_PATH);//获得拖拽的文件名
		SetDlgItemText(IDC_EDIT1, filePath);
		UpdateData(FALSE);
	}
	DragFinish(hDropInfo);
	CDialogEx::OnDropFiles(hDropInfo);
}

void CinjecDlg::printError(char* caption) {
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
	MessageBoxA((LPCTSTR)lpMsgBuf, caption, MB_OK);
	LocalFree(lpMsgBuf);
}

DWORD CinjecDlg::GetProcId(char* szProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return NULL;
	}
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	for (BOOL ret = Process32First(hSnapshot, &pe32); ret; ret = Process32Next(hSnapshot, &pe32))
	{
		// strupr()函数是将字符串转化为大写
		if (lstrcmp(strupr(pe32.szExeFile), strupr(szProcessName)) == 0)
		{
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

void CinjecDlg::SetDebugPrivileges()
{
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid);

		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &priv, sizeof(priv), NULL, NULL);

		CloseHandle(hToken);
	}
	else {
		printError(TEXT("SetDebugPrivileges Error!"));
	}
}

typedef struct _DATA
{
	DWORD dwCreateProcess;
	char cPath[MAX_PATH];
}DATA, * PDATA;

DWORD WINAPI RemoteThreadProc(LPVOID lpParam)
{
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = { 0 };
	PDATA pData = (PDATA)lpParam;

	// 定义API函数原型
	BOOL(__stdcall * MyCreateProcess)(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
									DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);

	MyCreateProcess = (BOOL (__stdcall*)(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
						DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION))
						pData->dwCreateProcess;
	// 调用
	MyCreateProcess(NULL, pData->cPath, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);

	return 0;
}

BOOL CinjecDlg::Inject(DWORD dwPID, char* szPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID lpData = NULL, lpCode = NULL;
	DATA Data = { 0 };
	CString str;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printError(TEXT("OpenProcess failed!"));
		return FALSE;
	}

	// 获取kernel32.dll中相关的导出函数CreateProcessA
	Data.dwCreateProcess = (DWORD)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CreateProcessA");

	// 路径
	lstrcpy(Data.cPath, szPath);

	// 在目标进程申请空间
	DWORD dwWriteNum = 0;
	lpData = VirtualAllocEx(hProcess, NULL, sizeof(Data)+1, MEM_COMMIT, PAGE_READWRITE);
	if (WriteProcessMemory(hProcess, lpData, &Data, sizeof(Data), &dwWriteNum) == FALSE)
	{
		printError(TEXT("WriteProcessMemory failed!"));
		return FALSE;
	}

	// 在目标进程空间申请的用于保存代码的长度
	lpCode = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (WriteProcessMemory(hProcess, lpCode, &RemoteThreadProc, 0x1000, &dwWriteNum) == FALSE)
	{
		printError(TEXT("WriteProcessMemory failed!"));
		return FALSE;
	}
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpCode, lpData, CREATE_SUSPENDED, NULL);

	ResumeThread(hThread);  // start inject thread
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

void CinjecDlg::OnBnClickedOk()
{
	DWORD dwPid;
	char szPath[MAX_PATH] = { 0 };
	char szProcessName[MAX_PATH] = { 0 };
	
	GetDlgItemText(IDC_EDIT1, szPath, MAX_PATH);
	GetDlgItemText(IDC_EDIT2, szProcessName, MAX_PATH);

	if (GetDlgItemText(IDC_EDIT1, szPath, MAX_PATH) == 0)
	{
		MessageBox(TEXT("请输入注入内容路径。"), TEXT("Tip"), MB_OK);
		return;
	}
	if (GetDlgItemText(IDC_EDIT2, szProcessName, MAX_PATH) == 0)
	{
		MessageBox(TEXT("请输入注入进程名称。"), TEXT("Tip"), MB_OK);
		return;
	}

	if (!PathFileExists(szPath)) {
		MessageBoxA("注入路径文件不存在，请确认注入路径输入无误。", "Error", MB_OK);
		return;
	}

	dwPid = GetProcId(szProcessName);
	if (dwPid == 0) {
		MessageBoxA("找不到相应进程，请确认进程名称输入无误。", "Error", MB_OK);
		return;
	}

	SetDebugPrivileges();

	Inject(dwPid, szPath);
}

