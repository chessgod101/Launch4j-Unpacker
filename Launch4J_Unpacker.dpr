program Launch4J_Unpacker;

uses
  Forms,
  MainFrm in 'MainFrm.pas' {LJUFormMain};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TLJUFormMain, LJUFormMain);
  Application.Run;
end.
