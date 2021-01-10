unit MainFrm;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ImageHlp, StdCtrls, ShellAPI;

type
  TLJUFormMain = class(TForm)
    ExtractBtn: TButton;
    PathEdit: TEdit;
    ChooseBtn: TButton;
    OpenDialog1: TOpenDialog;
    Label1: TLabel;
    ExitBtn: TButton;
    procedure ExtractBtnClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure ChooseBtnClick(Sender: TObject);
    procedure ExitBtnClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
    protected
    procedure WMDropFiles(var Msg: TMessage); message WM_DROPFILES;
  end;

   TImageOptionalHeader64 = record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    ImageBase: Uint64;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: Uint64;
    SizeOfStackCommit: Uint64;
    SizeOfHeapReserve: Uint64;
    SizeOfHeapCommit: Uint64;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TImageDataDirectory;
   end;

var
  LJUFormMain: TLJUFormMain;
 Const FooterWPad: byte =$26;
implementation

{$R *.dfm}
Function FindFooterStart(bArr:PByte; SIZE:cardinal):Cardinal;
var
  I:cardinal;
CONST
  zipFooter:array[0..3] of byte=($50, $4B, $05, $06);
Begin
  Result:=$FFFFFFFF;
  for I := 0 to SIZE do Begin
    if CompareMem(@bArr[I],@zipFooter[0],4) = true then Begin
      Result:=I;
      Exit;
    End;
  End;
End;

Function RemExt(FName:WideString):WideString;
var
  len:cardinal;
Begin
  len:=length(Fname)-length(ExtractFileExt(FName));
  SetLength(result,len);
  CopyMemory(@result[1],@FName[1],len*2);
End;

Function SaveFile(FileName:wideString;data:Pbyte;size:Cardinal;overwrite:Boolean):Boolean;
var
 fh:THandle;
 tmp:cardinal;
Begin
 result:=false;
 if overwrite=true then
  tmp:=CREATE_ALWAYS
 else
  tmp:=CREATE_NEW;
 fh:=CreateFile(@FileName[1],GENERIC_WRITE,0,NIL,tmp,FILE_ATTRIBUTE_NORMAL,0);
 if fh=INVALID_HANDLE_VALUE then exit;
  if WriteFile(fh,data[0],size,tmp,nil)=true then result:=true;
 CloseHandle(fh);
End;

Function GetOffsetOfAppendedData(fH:THandle;Var offset,certOffset,certSize:Cardinal):Boolean;
var
  dh:tImageDosHeader;
  pe:timageFileHeader;
  op:TImageOptionalHeader;
  op64:TImageOptionalHeader64;
  secH:TImageSectionHeader;
  tmp,fp:Cardinal;
  aType:Word;
Begin
  result:=false;
  offset:=0;
  SetFilePointer(fH,0,nil,FILE_BEGIN);
  if ReadFile(fH,dh,sizeof(TImageDosHeader),tmp,nil)=false then Exit;
  if (dh.e_magic<>23117)and(dh._lfanew>=$1000) then Exit;
  SetFilePointer(fH,dh._lfanew+4,nil,FILE_BEGIN);
  fp:=dh._lfanew+4+sizeof(TImageFileHeader);
  if ReadFile(fH,pe,sizeof(TImageFileHeader),tmp,nil)=false then exit;
  if ReadFile(fH,aType,2,tmp,nil)=false then exit;
  SetFilePointer(fH,fp,nil,FILE_BEGIN);
  if aType= $20b then begin   //x64 exe
    if ReadFile(fH,op64,SizeOf(TImageOptionalHeader64),tmp,nil)=false then exit;
    certOffset:=op64.DataDirectory[4].VirtualAddress;
    certSize:=op64.DataDirectory[4].SIZE;
  end
  else
  Begin //x86
    if ReadFile(fH,op,sizeof(TImageOptionalHeader),tmp,nil)=false then exit;
    certOffset:=op.DataDirectory[4].VirtualAddress;
    certSize:=op.DataDirectory[4].SIZE;
  End;
  SetFilePointer(fH,(integer(fp)+pe.SizeOfOptionalHeader)+(sizeof(TImageSectionHeader)*(pe.NumberOfSections-1)),nil,FILE_BEGIN);
  if ReadFile(fH,secH,sizeof(TImageSectionHeader),tmp,nil)=false then exit;
  tmp:=secH.SizeOfRawData;
  offset:=tmp+secH.PointerToRawData;
  result:=true;
End;

procedure TLJUFormMain.ExtractBtnClick(Sender: TObject);
var
  fh:THandle;
  AOffset,fSize,bSize,tmp,certSize,certOffset:Cardinal;
  target,sFileStr:WideString;
  Buffer:Array of Byte;
begin
  target:=PathEdit.Text;
  if FileExists(target)=false then begin
    MessageBox(Application.Handle,PChar('File Not Found!'),PChar('Launch4j Unpacker'),MB_OK);
    Exit;
  End;
  fh:=CreateFileW(@target[1],GENERIC_READ,FILE_SHARE_READ,NIL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, 0);

  if fh=INVALID_HANDLE_VALUE then Begin
    MessageBox(Application.Handle,PChar('Cannot open file.'),PChar('Launch4j Unpacker'),MB_OK);
    exit;
  End;

  if GetOffsetOfAppendedData(fh,AOffset,certOffset,certSize)=false then Begin
    MessageBox(Application.Handle,PChar('Cannot parse header.'),PChar('Launch4j Unpacker'),MB_OK);
    CloseHandle(fh);
    Exit;
  End;

  fSize:=GetFileSize(fh, nil);

  if fSize<=Aoffset then Begin
    MessageBox(Application.Handle,PChar('Not a Launch4J Application!'),PChar('Launch4j Unpacker'),MB_OK);
    CloseHandle(fh);
    Exit;
  End;

  if certSize>0 then begin   //removes sign4j certificate
    fSize:=fSize-certSize;
    Setlength(Buffer,FooterWPad);
    SetFilePointer(fh,fSize-FooterWPad,nil,FILE_BEGIN);
    ReadFile(fh,Buffer[0],FooterWPad,tmp,nil);
    tmp:=FindFooterStart(@Buffer[0],FooterWPad);
    if tmp<>$FFFFFFFF then
    fSize:=fSize-(FooterWPad-tmp)+$16
  else Begin
    CloseHandle(fh);
    MessageBox(Application.Handle,PChar('Failed To Find Zip Footer!'),PChar('Launch4j Unpacker'),MB_OK);
    Exit;
  End;
  End;

  SetFilePointer(fh,AOffset,nil,FILE_BEGIN);
  bSize:=fSize-AOffset;
  SetLength(Buffer,fSize-AOffset);
  ReadFile(fh, Buffer[0],fSize-AOffset,tmp,nil);
  CloseHandle(fh);
  if certSize>0 then begin
    Buffer[fSize-AOffset-1]:=0;
    Buffer[fSize-AOffset-2]:=0;
  end;

  if (Buffer[0]<>$50) and (Buffer [1]<>$4B) then Begin //check for zip
    MessageBox(Application.Handle,PChar('File not a valid Launch4J application!'),PChar('Launch4j Unpacker'),MB_OK);
    exit;
  End;

  sFileStr:=(ExtractFilePath(target));
  sFileStr:=WideString(sFileStr+remExt((ExtractFileName((target))))+'_unpacked.jar');

  if SaveFile(sFileStr, @Buffer[0],bSize, true)=false then Begin
    MessageBox(Application.Handle,PChar('Could not create extracted file!'),PChar('Launch4j Unpacker'),MB_OK);
    exit;
  End;

  MessageBeep(MB_ICONINFORMATION);
  MessageBox(Application.Handle,PChar('Unpacked Successfully!'),PChar('Launch4j Unpacker'),MB_OK);
end;

procedure TLJUFormMain.ChooseBtnClick(Sender: TObject);
begin
  if OpenDialog1.Execute=true then
    PathEdit.Text:=OpenDialog1.FileName;
end;

procedure TLJUFormMain.ExitBtnClick(Sender: TObject);
begin
  ExitProcess(0);
end;

procedure TLJUFormMain.FormCreate(Sender: TObject);
begin
  DragAcceptFiles(Handle,true);
end;

procedure TLJUFormMain.FormDestroy(Sender: TObject);
begin
  DragAcceptFiles(Handle,false);
end;

procedure TLJUFormMain.WMDropFiles(var Msg: TMessage);
var
  l:cardinal;
  s,ext:string;
Begin
  l:=DragQueryFile(Msg.WParam,0,nil,0)+1;
  SetLength(s,l);
  DragQueryFile(Msg.WParam,0,Pointer(s),l);
  ext:= lowercase(TrimRight(ExtractFileExt(s)));
  if ext='.exe' then
    PathEdit.Text:=s;
End;

end.
